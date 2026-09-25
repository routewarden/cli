package protocol

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// POP3InspectorOptions configures the POP3 proxy inspector.
type POP3InspectorOptions struct {
	OnAuthFailure func()
}

// POP3Proxy handles inspection and relaying of a POP3 session.
type POP3Proxy struct {
	client   net.Conn
	upstream net.Conn
	opts     POP3InspectorOptions

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// NewPOP3Proxy creates a new POP3Proxy session.
func NewPOP3Proxy(client, upstream net.Conn, opts POP3InspectorOptions) *POP3Proxy {
	return &POP3Proxy{
		client:   client,
		upstream: upstream,
		opts:     opts,
	}
}

// Run executes the POP3 inspection and relay loop.
func (p *POP3Proxy) Run() (ProxyResult, bool, string) {
	clientReader := bufio.NewReader(p.client)
	upstreamReader := bufio.NewReader(p.upstream)

	// Step 1: Read greeting from upstream, e.g. "+OK Dovecot ready."
	greeting, err := upstreamReader.ReadString('\n')
	if err != nil {
		return p.result(), true, "failed reading POP3 greeting: " + err.Error()
	}
	p.bytesOut.Add(int64(len(greeting)))
	if _, err := p.client.Write([]byte(greeting)); err != nil {
		return p.result(), false, ""
	}

	// Step 2: Command/Response loop
	for {
		p.client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		clientLine, err := clientReader.ReadString('\n')
		if err != nil {
			return p.result(), false, ""
		}
		p.bytesIn.Add(int64(len(clientLine)))

		trimmed := strings.TrimSpace(clientLine)
		upper := strings.ToUpper(trimmed)

		// Forward client command to upstream
		if _, err := p.upstream.Write([]byte(clientLine)); err != nil {
			return p.result(), false, ""
		}

		// STLS command (Start TLS)
		if upper == "STLS" {
			resp, err := upstreamReader.ReadString('\n')
			if err != nil {
				return p.result(), false, ""
			}
			p.bytesOut.Add(int64(len(resp)))
			if _, err := p.client.Write([]byte(resp)); err != nil {
				return p.result(), false, ""
			}

			if strings.HasPrefix(strings.ToUpper(resp), "+OK") {
				// TLS negotiation begins
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

		// Read response from upstream
		// If command produces multi-line response (e.g. CAPA, LIST, UIDL)
		if isPOP3MultiLineCmd(upper) {
			resp, err := readPOP3MultiLineResponse(upstreamReader)
			if err != nil {
				return p.result(), false, ""
			}
			p.bytesOut.Add(int64(len(resp)))
			if _, err := p.client.Write([]byte(resp)); err != nil {
				return p.result(), false, ""
			}
			continue
		}

		// Single line response
		resp, err := upstreamReader.ReadString('\n')
		if err != nil {
			return p.result(), false, ""
		}
		p.bytesOut.Add(int64(len(resp)))
		if _, err := p.client.Write([]byte(resp)); err != nil {
			return p.result(), false, ""
		}

		// If PASS command failed
		if strings.HasPrefix(upper, "PASS ") {
			if strings.HasPrefix(strings.ToUpper(resp), "-ERR") {
				if p.opts.OnAuthFailure != nil {
					p.opts.OnAuthFailure()
				}
			}
		}

		if upper == "QUIT" {
			return p.result(), false, ""
		}
	}
}

func (p *POP3Proxy) result() ProxyResult {
	return ProxyResult{
		BytesIn:  p.bytesIn.Load(),
		BytesOut: p.bytesOut.Load(),
	}
}

func isPOP3MultiLineCmd(upper string) bool {
	return upper == "CAPA" || strings.HasPrefix(upper, "LIST") && upper == "LIST" ||
		strings.HasPrefix(upper, "UIDL") && upper == "UIDL" ||
		strings.HasPrefix(upper, "TOP ") || strings.HasPrefix(upper, "RETR ")
}

func readPOP3MultiLineResponse(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	firstLine, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	sb.WriteString(firstLine)

	// If error response (-ERR), there is no multi-line body
	if strings.HasPrefix(strings.ToUpper(firstLine), "-ERR") {
		return sb.String(), nil
	}

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return sb.String(), err
		}
		sb.WriteString(line)
		if line == ".\r\n" || line == ".\n" {
			break
		}
	}
	return sb.String(), nil
}
