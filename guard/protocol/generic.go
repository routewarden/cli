// Package protocol contains protocol-specific TCP inspectors for rwarden guard.
// Each inspector peeks at the byte stream without consuming it, applies
// protocol-level policy, then either proxies the full stream or applies a
// response action.
package protocol

import (
	"io"
	"net"
	"sync/atomic"
)

// ProxyResult is returned by a proxy session when it completes.
type ProxyResult struct {
	BytesIn  int64
	BytesOut int64
	Err      error
}

// Proxy performs a bidirectional io.Copy between client and upstream.
// It blocks until both directions are done and returns byte counts.
func Proxy(client, upstream net.Conn) ProxyResult {
	var bytesIn, bytesOut atomic.Int64
	done := make(chan struct{}, 2)

	copy := func(dst, src net.Conn, counter *atomic.Int64) {
		n, _ := io.Copy(dst, src)
		counter.Add(n)
		// Half-close: signal EOF to the other side
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}

	go copy(upstream, client, &bytesIn)
	go copy(client, upstream, &bytesOut)

	<-done
	<-done

	return ProxyResult{
		BytesIn:  bytesIn.Load(),
		BytesOut: bytesOut.Load(),
	}
}

// DialUpstream opens a TCP connection to the upstream address with a
// reasonable timeout.
func DialUpstream(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 10e9) // 10s
}
