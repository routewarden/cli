package protocol

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// IMAPInspectorOptions configures the IMAP proxy inspector.
type IMAPInspectorOptions struct {
	OnAuthFailure func()
}

// IMAPProxy handles inspection and relaying of an IMAP session.
type IMAPProxy struct {
	client   net.Conn
	upstream net.Conn
	opts     IMAPInspectorOptions

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// NewIMAPProxy creates a new IMAPProxy session.
func NewIMAPProxy(client, upstream net.Conn, opts IMAPInspectorOptions) *IMAPProxy {
	return &IMAPProxy{
		client:   client,
		upstream: upstream,
		opts:     opts,
	}
}

// Run executes the IMAP inspection and relay loop.
func (p *IMAPProxy) Run() (ProxyResult, bool, string) {
	clientReader := bufio.NewReader(p.client)
	upstreamReader := bufio.NewReader(p.upstream)

	// Step 1: Upstream greeting banner (e.g. "* OK IMAP4rev1 ready")
	greeting, err := upstreamReader.ReadString('\n')
	if err != nil {
		return p.result(), true, "failed reading IMAP greeting: " + err.Error()
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
		parts := strings.SplitN(trimmed, " ", 3)
		tag := ""
		cmd := ""
		if len(parts) >= 1 {
			tag = parts[0]
		}
		if len(parts) >= 2 {
			cmd = strings.ToUpper(parts[1])
		}

		// Forward client command to upstream
		if _, err := p.upstream.Write([]byte(clientLine)); err != nil {
			return p.result(), false, ""
		}

		// Read upstream responses until the tagged completion line arrives
		// Tagged completion line starts with tag + " " (e.g. "A01 OK", "A01 NO", "A01 BAD")
		for {
			respLine, err := upstreamReader.ReadString('\n')
			if err != nil {
				return p.result(), false, ""
			}
			p.bytesOut.Add(int64(len(respLine)))
			if _, err := p.client.Write([]byte(respLine)); err != nil {
				return p.result(), false, ""
			}

			respTrimmed := strings.TrimSpace(respLine)

			// Check if this response line finishes the current command
			if tag != "" && strings.HasPrefix(respTrimmed, tag+" ") {
				statusPart := strings.TrimPrefix(respTrimmed, tag+" ")
				statusUpper := strings.ToUpper(statusPart)

				// Handle STARTTLS
				if cmd == "STARTTLS" && strings.HasPrefix(statusUpper, "OK") {
					p.client.SetReadDeadline(time.Time{})
					p.upstream.SetReadDeadline(time.Time{})

					clientWrapper := &bufferedConn{Reader: io.MultiReader(clientReader, p.client), Conn: p.client}
					upstreamWrapper := &bufferedConn{Reader: io.MultiReader(upstreamReader, p.upstream), Conn: p.upstream}

					rawRes := Proxy(clientWrapper, upstreamWrapper)
					p.bytesIn.Add(rawRes.BytesIn)
					p.bytesOut.Add(rawRes.BytesOut)
					return p.result(), false, ""
				}

				// Handle LOGIN / AUTHENTICATE failure
				if (cmd == "LOGIN" || cmd == "AUTHENTICATE") &&
					(strings.HasPrefix(statusUpper, "NO") || strings.HasPrefix(statusUpper, "BAD")) {
					if p.opts.OnAuthFailure != nil {
						p.opts.OnAuthFailure()
					}
				}

				break // Finished handling this tagged command
			}

			// If untagged or continuation (+ ...), keep looping
		}

		if cmd == "LOGOUT" {
			return p.result(), false, ""
		}
	}
}

func (p *IMAPProxy) result() ProxyResult {
	return ProxyResult{
		BytesIn:  p.bytesIn.Load(),
		BytesOut: p.bytesOut.Load(),
	}
}
