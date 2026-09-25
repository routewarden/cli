package protocol

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// SMTPInspectorOptions configures the SMTP proxy behavior.
type SMTPInspectorOptions struct {
	BlockedSenderDomains []string
	RequireSTARTTLS      bool
	OnAuthFailure        func()
}

// SMTPProxy handles inspection and relaying of an SMTP session.
type SMTPProxy struct {
	client   net.Conn
	upstream net.Conn
	opts     SMTPInspectorOptions

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// NewSMTPProxy creates a new SMTPProxy session.
func NewSMTPProxy(client, upstream net.Conn, opts SMTPInspectorOptions) *SMTPProxy {
	return &SMTPProxy{
		client:   client,
		upstream: upstream,
		opts:     opts,
	}
}

// Run executes the SMTP inspection and proxying loop.
// Returns (result, wasBlocked, reason).
func (p *SMTPProxy) Run() (ProxyResult, bool, string) {
	clientReader := bufio.NewReader(p.client)
	upstreamReader := bufio.NewReader(p.upstream)

	// Step 1: Upstream sends greeting banner, e.g. "220 mail.example.com ESMTP..."
	greeting, err := readSMTPResponse(upstreamReader)
	if err != nil {
		return p.result(), true, "failed reading upstream greeting: " + err.Error()
	}
	if err := p.writeClient(greeting); err != nil {
		return p.result(), false, ""
	}

	// Step 2: Command / Response loop
	inAuthExchange := false

	for {
		p.client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		clientLine, err := clientReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return p.result(), false, ""
			}
			return p.result(), false, ""
		}
		p.bytesIn.Add(int64(len(clientLine)))

		trimmed := strings.TrimSpace(clientLine)
		upper := strings.ToUpper(trimmed)

		// If in multi-step AUTH (e.g. AUTH LOGIN or AUTH PLAIN challenge/response)
		if inAuthExchange {
			if err := p.writeUpstream(clientLine); err != nil {
				return p.result(), false, ""
			}
			resp, err := readSMTPResponse(upstreamReader)
			if err != nil {
				return p.result(), false, ""
			}
			if err := p.writeClient(resp); err != nil {
				return p.result(), false, ""
			}

			// Check auth outcome
			code := responseCode(resp)
			if code == 235 {
				// 235 Authentication successful
				inAuthExchange = false
			} else if code == 334 {
				// 334 Continue challenge
				inAuthExchange = true
			} else if code >= 400 {
				// Auth failure (535, 501, 504, etc.)
				inAuthExchange = false
				if p.opts.OnAuthFailure != nil {
					p.opts.OnAuthFailure()
				}
			}
			continue
		}

		// Check MAIL FROM:<sender>
		if strings.HasPrefix(upper, "MAIL FROM:") {
			sender := extractEmailAddress(trimmed[10:])
			domain := extractDomain(sender)

			if p.isDomainBlocked(domain) {
				rejectMsg := fmt.Sprintf("550 5.7.1 Sender domain <%s> rejected by RouteWarden Guard\r\n", domain)
				_ = p.writeClient(rejectMsg)
				return p.result(), true, fmt.Sprintf("blocked sender domain: %s", domain)
			}
		}

		// Check AUTH command initiation
		if strings.HasPrefix(upper, "AUTH ") {
			if err := p.writeUpstream(clientLine); err != nil {
				return p.result(), false, ""
			}
			resp, err := readSMTPResponse(upstreamReader)
			if err != nil {
				return p.result(), false, ""
			}
			if err := p.writeClient(resp); err != nil {
				return p.result(), false, ""
			}

			code := responseCode(resp)
			if code == 334 {
				inAuthExchange = true
			} else if code == 235 {
				inAuthExchange = false
			} else if code >= 400 {
				inAuthExchange = false
				if p.opts.OnAuthFailure != nil {
					p.opts.OnAuthFailure()
				}
			}
			continue
		}

		// Check STARTTLS
		if upper == "STARTTLS" {
			if err := p.writeUpstream(clientLine); err != nil {
				return p.result(), false, ""
			}
			resp, err := readSMTPResponse(upstreamReader)
			if err != nil {
				return p.result(), false, ""
			}
			if err := p.writeClient(resp); err != nil {
				return p.result(), false, ""
			}

			if strings.HasPrefix(resp, "220") {
				// TLS negotiation begins — stream is encrypted from here on.
				// Reset read deadlines and switch to raw bidirectional proxy.
				p.client.SetReadDeadline(time.Time{})
				p.upstream.SetReadDeadline(time.Time{})

				clientWrapper := &bufferedConn{Reader: io.MultiReader(clientReader, p.client), Conn: p.client}
				upstreamWrapper := &bufferedConn{Reader: io.MultiReader(upstreamReader, p.upstream), Conn: p.upstream}

				rawRes := Proxy(clientWrapper, upstreamWrapper)
				p.bytesIn.Add(rawRes.BytesIn)
				p.bytesOut.Add(rawRes.BytesOut)
				return p.result(), false, ""
			}
			continue
		}

		// Check DATA command
		if upper == "DATA" {
			if err := p.writeUpstream(clientLine); err != nil {
				return p.result(), false, ""
			}
			resp, err := readSMTPResponse(upstreamReader)
			if err != nil {
				return p.result(), false, ""
			}
			if err := p.writeClient(resp); err != nil {
				return p.result(), false, ""
			}

			// If server answered 354 Start mail input
			if strings.HasPrefix(resp, "354") {
				// Relay email body until ".\r\n"
				for {
					bodyLine, err := clientReader.ReadString('\n')
					if err != nil {
						return p.result(), false, ""
					}
					p.bytesIn.Add(int64(len(bodyLine)))
					if err := p.writeUpstream(bodyLine); err != nil {
						return p.result(), false, ""
					}
					if bodyLine == ".\r\n" || bodyLine == ".\n" {
						break
					}
				}
				// Read server response to DATA completion (e.g. 250 2.0.0 Ok: queued)
				dataResp, err := readSMTPResponse(upstreamReader)
				if err != nil {
					return p.result(), false, ""
				}
				if err := p.writeClient(dataResp); err != nil {
					return p.result(), false, ""
				}
			}
			continue
		}

		// Check QUIT
		if upper == "QUIT" {
			_ = p.writeUpstream(clientLine)
			resp, _ := readSMTPResponse(upstreamReader)
			_ = p.writeClient(resp)
			return p.result(), false, ""
		}

		// Default: Forward command to upstream, relay response to client
		if err := p.writeUpstream(clientLine); err != nil {
			return p.result(), false, ""
		}
		resp, err := readSMTPResponse(upstreamReader)
		if err != nil {
			return p.result(), false, ""
		}
		if err := p.writeClient(resp); err != nil {
			return p.result(), false, ""
		}
	}
}

func (p *SMTPProxy) writeClient(s string) error {
	b := []byte(s)
	n, err := p.client.Write(b)
	p.bytesOut.Add(int64(n))
	return err
}

func (p *SMTPProxy) writeUpstream(s string) error {
	b := []byte(s)
	_, err := p.upstream.Write(b)
	return err
}

func (p *SMTPProxy) result() ProxyResult {
	return ProxyResult{
		BytesIn:  p.bytesIn.Load(),
		BytesOut: p.bytesOut.Load(),
	}
}

func (p *SMTPProxy) isDomainBlocked(domain string) bool {
	if domain == "" {
		return false
	}
	domain = strings.ToLower(domain)
	for _, pattern := range p.opts.BlockedSenderDomains {
		pat := strings.ToLower(strings.TrimSpace(pattern))
		if pat == "" {
			continue
		}
		// Exact match
		if pat == domain {
			return true
		}
		// Wildcard match e.g. *.spam.com or *.ru
		matched, err := filepath.Match(pat, domain)
		if err == nil && matched {
			return true
		}
		// Suffix match for *.domain
		if strings.HasPrefix(pat, "*.") && strings.HasSuffix(domain, pat[1:]) {
			return true
		}
	}
	return false
}

// readSMTPResponse reads a single or multi-line SMTP reply from reader.
// Format: "XYZ-text\r\n" for intermediate lines, "XYZ text\r\n" for final line.
func readSMTPResponse(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return sb.String(), err
		}
		sb.WriteString(line)
		// Check for completion: length >= 4 and 4th char is space
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
		// Also fallback if not formatted standardly but ends with newline
		if len(line) < 4 {
			break
		}
	}
	return sb.String(), nil
}

func responseCode(resp string) int {
	if len(resp) < 3 {
		return 0
	}
	var code int
	fmt.Sscanf(resp[:3], "%d", &code)
	return code
}

func extractEmailAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	start := strings.Index(raw, "<")
	end := strings.Index(raw, ">")
	if start != -1 && end != -1 && end > start {
		return raw[start+1 : end]
	}
	return strings.Trim(raw, "<> \t\r\n")
}

func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
