package protocol

import (
	"io"
	"net"
	"sync/atomic"
	"time"
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

	type closeWriter interface {
		CloseWrite() error
	}
	type closeReader interface {
		CloseRead() error
	}

	copy := func(dst, src net.Conn, counter *atomic.Int64) {
		n, _ := io.Copy(dst, src)
		counter.Add(n)
		// Half-close: signal EOF to the peer on the dst side without killing
		// the concurrent goroutine that is still reading from dst.
		if cw, ok := dst.(closeWriter); ok {
			// Preferred path: sends FIN on dst's write half only.
			_ = cw.CloseWrite()
		} else if cr, ok := src.(closeReader); ok {
			// Fallback: close the read half of src so the remote sees EOF,
			// without disturbing dst's ongoing read in the other goroutine.
			_ = cr.CloseRead()
		} else {
			// If neither half-close is available on non-TCP conn wrappers,
			// set a brief read deadline on dst so any stuck io.Copy unblocks.
			_ = dst.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
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

// DialUpstream opens a TCP connection to the upstream address with a reasonable timeout.
func DialUpstream(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 10*time.Second)
}

// BufferedConn wraps a reader and a net.Conn so that peeked or buffered
// bytes can be seamlessly read before reading from the underlying conn.
type BufferedConn struct {
	io.Reader
	net.Conn
}

func (b *BufferedConn) Read(p []byte) (int, error) {
	if b.Reader != nil {
		n, err := b.Reader.Read(p)
		if n > 0 {
			if err == io.EOF {
				b.Reader = nil
				return n, nil
			}
			return n, err
		}
		if err == io.EOF {
			b.Reader = nil
		} else if err != nil {
			return 0, err
		}
	}
	return b.Conn.Read(p)
}

// CloseWrite forwards half-close to the underlying Conn if supported.
func (b *BufferedConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// CloseRead forwards half-close to the underlying Conn if supported.
func (b *BufferedConn) CloseRead() error {
	if cr, ok := b.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}
