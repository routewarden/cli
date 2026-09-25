package protocol

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

// SSHInspector inspects SSH connections at the protocol level.
// It validates the SSH version banner and monitors SSH_MSG_USERAUTH
// failure patterns to detect brute-force attacks.
type SSHInspector struct{}

// SSHResult is the outcome of SSHInspector.Inspect.
type SSHResult struct {
	ClientVersion string // e.g. "SSH-2.0-OpenSSH_8.9"
	IsSSH1        bool   // true if client advertises SSH-1.x (reject these)
	Valid         bool
}

// Inspect reads the SSH client banner from conn (non-destructively via
// a bufio.Reader) and returns metadata. The reader is returned so the
// full stream can still be proxied after inspection.
func (SSHInspector) Inspect(conn net.Conn) (*bufio.Reader, SSHResult) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return br, SSHResult{}
	}
	line = strings.TrimSpace(line)

	result := SSHResult{
		ClientVersion: line,
		Valid:         strings.HasPrefix(line, "SSH-"),
	}
	if strings.HasPrefix(line, "SSH-1.") {
		result.IsSSH1 = true
	}
	return br, result
}

// SSHAuthMonitor wraps an upstream connection and watches the proxied byte
// stream for SSH_MSG_USERAUTH_FAILURE messages (message type 51).
// On each failure it calls onFailure(). The underlying stream is proxied
// transparently — no bytes are dropped.
type SSHAuthMonitor struct {
	// AuthFailures is incremented each time a USERAUTH_FAILURE is detected.
	AuthFailures int
	onFailure    func()
}

// NewSSHAuthMonitor returns a monitor that calls onFailure on each detected
// authentication failure message from the upstream server.
func NewSSHAuthMonitor(onFailure func()) *SSHAuthMonitor {
	return &SSHAuthMonitor{onFailure: onFailure}
}

// WrapUpstream wraps the upstream connection so that data flowing back to
// the client is scanned for SSH_MSG_USERAUTH_FAILURE patterns.
// It returns a net.Conn whose Read scans for failure messages.
func (m *SSHAuthMonitor) WrapUpstream(upstream net.Conn) net.Conn {
	return &sshMonitorConn{Conn: upstream, monitor: m}
}

// sshMonitorConn is a net.Conn that scans outgoing (server→client) data
// for SSH_MSG_USERAUTH_FAILURE (message type byte 0x33 = 51).
type sshMonitorConn struct {
	net.Conn
	monitor *SSHAuthMonitor
	buf     []byte
}

func (c *sshMonitorConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.buf = append(c.buf, p[:n]...)
		c.scan()
	}
	return n, err
}

// scan looks for SSH binary protocol packets with type SSH_MSG_USERAUTH_FAILURE (51).
// SSH packet structure: uint32 packet_length | byte padding_length | byte msg_type | ...
func (c *sshMonitorConn) scan() {
	for len(c.buf) >= 6 {
		// packet_length (4 bytes, big-endian)
		pktLen := int(c.buf[0])<<24 | int(c.buf[1])<<16 | int(c.buf[2])<<8 | int(c.buf[3])
		if pktLen < 2 || pktLen > 35000 {
			c.buf = c.buf[1:] // resync
			continue
		}
		total := 4 + pktLen
		if len(c.buf) < total {
			break // wait for more data
		}
		paddingLen := int(c.buf[4])
		msgType := c.buf[5]
		_ = paddingLen

		const sshMsgUserAuthFailure = 51
		if msgType == sshMsgUserAuthFailure {
			c.monitor.AuthFailures++
			if c.monitor.onFailure != nil {
				c.monitor.onFailure()
			}
		}
		c.buf = c.buf[total:]
	}
	// Keep at most 64KB of unprocessed data to bound memory
	if len(c.buf) > 65536 {
		c.buf = c.buf[len(c.buf)-65536:]
	}
}

// RejectSSH1 sends a polite SSH-2.0 banner and then a disconnect message
// to a client that advertised SSH-1.x, then closes the connection.
func RejectSSH1(conn net.Conn) {
	banner := "SSH-2.0-RouteWarden_Guard\r\n"
	conn.Write([]byte(banner))
	// SSH_MSG_DISCONNECT (1) with reason 7 (PROTOCOL_VERSION_NOT_SUPPORTED)
	msg := buildSSHDisconnect(7, "SSH-1.x not supported")
	conn.Write(msg)
	conn.Close()
}

// RejectSSH sends a disconnect message and closes the connection.
func RejectSSH(conn net.Conn, reason string) {
	conn.Write([]byte("SSH-2.0-RouteWarden_Guard\r\n"))
	msg := buildSSHDisconnect(11, reason)
	conn.Write(msg)
	conn.Close()
}

// buildSSHDisconnect creates a minimal SSH_MSG_DISCONNECT packet.
func buildSSHDisconnect(code uint32, message string) []byte {
	// msg_type(1) + reason_code(4) + string_len(4) + string + lang_len(4)
	msgLen := 1 + 4 + 4 + len(message) + 4
	padding := 8 - (msgLen % 8)
	if padding < 4 {
		padding += 8
	}
	pktLen := 1 + msgLen + padding

	buf := &bytes.Buffer{}
	// packet_length
	fmt.Fprintf(buf, "%c%c%c%c",
		byte(pktLen>>24), byte(pktLen>>16), byte(pktLen>>8), byte(pktLen))
	// padding_length
	buf.WriteByte(byte(padding))
	// SSH_MSG_DISCONNECT = 1
	buf.WriteByte(1)
	// reason_code (uint32)
	fmt.Fprintf(buf, "%c%c%c%c",
		byte(code>>24), byte(code>>16), byte(code>>8), byte(code))
	// message (string: uint32 length + bytes)
	mlen := uint32(len(message))
	fmt.Fprintf(buf, "%c%c%c%c", byte(mlen>>24), byte(mlen>>16), byte(mlen>>8), byte(mlen))
	buf.WriteString(message)
	// language tag (empty string: uint32 zero)
	buf.Write([]byte{0, 0, 0, 0})
	// random padding
	buf.Write(make([]byte, padding))

	return buf.Bytes()
}
