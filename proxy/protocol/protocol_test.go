package protocol

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type mockCloseWriterConn struct {
	net.Conn
	closedWrite bool
}

func (m *mockCloseWriterConn) CloseWrite() error {
	m.closedWrite = true
	return nil
}

func TestProxy(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyUpstream, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyUpstream.Close()
	defer upstreamConn.Close()

	// Run proxy in background
	proxyDone := make(chan ProxyResult, 1)
	go func() {
		proxyDone <- Proxy(proxyClient, proxyUpstream)
	}()

	// Client sends data, upstream echoes back
	clientPayload := []byte("hello from client")
	upstreamPayload := []byte("hello from upstream")

	go func() {
		buf := make([]byte, len(clientPayload))
		_, _ = io.ReadFull(upstreamConn, buf)
		_, _ = upstreamConn.Write(upstreamPayload)
		_ = upstreamConn.Close()
	}()

	go func() {
		_, _ = clientConn.Write(clientPayload)
		buf := make([]byte, len(upstreamPayload))
		_, _ = io.ReadFull(clientConn, buf)
		_ = clientConn.Close()
	}()

	res := <-proxyDone
	if res.BytesIn != int64(len(clientPayload)) {
		t.Errorf("expected BytesIn=%d, got %d", len(clientPayload), res.BytesIn)
	}
	if res.BytesOut != int64(len(upstreamPayload)) {
		t.Errorf("expected BytesOut=%d, got %d", len(upstreamPayload), res.BytesOut)
	}
}

func TestBufferedConn_Read(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	peeked := []byte("peeked-prefix:")
	buffered := &BufferedConn{
		Reader: io.MultiReader(bytes.NewReader(peeked), c1),
		Conn:   c1,
	}

	go func() {
		_, _ = c2.Write([]byte("stream-body"))
	}()

	buf := make([]byte, len(peeked)+len("stream-body"))
	_, err := io.ReadFull(buffered, buf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}

	expected := "peeked-prefix:stream-body"
	if string(buf) != expected {
		t.Errorf("expected %q, got %q", expected, string(buf))
	}
}

func TestBufferedConn_ReaderFallback(t *testing.T) {
	// Test 1: bytes.NewReader(peeked) transitions to reading from Conn
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	peeked := []byte("prefix-data:")
	buffered := &BufferedConn{
		Reader: bytes.NewReader(peeked),
		Conn:   c1,
	}

	go func() {
		_, _ = c2.Write([]byte("conn-data"))
	}()

	buf := make([]byte, len(peeked)+len("conn-data"))
	_, err := io.ReadFull(buffered, buf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if string(buf) != "prefix-data:conn-data" {
		t.Errorf("expected 'prefix-data:conn-data', got %q", string(buf))
	}

	// Test 2: bytes.NewReader(nil) immediately reads from Conn
	c3, c4 := net.Pipe()
	defer c3.Close()
	defer c4.Close()

	emptyBuffered := &BufferedConn{
		Reader: bytes.NewReader(nil),
		Conn:   c3,
	}

	go func() {
		_, _ = c4.Write([]byte("direct-conn-data"))
	}()

	buf2 := make([]byte, len("direct-conn-data"))
	_, err = io.ReadFull(emptyBuffered, buf2)
	if err != nil {
		t.Fatalf("unexpected read error for empty Reader: %v", err)
	}
	if string(buf2) != "direct-conn-data" {
		t.Errorf("expected 'direct-conn-data', got %q", string(buf2))
	}

	// Test 3: Reader is nil immediately reads from Conn
	c5, c6 := net.Pipe()
	defer c5.Close()
	defer c6.Close()

	nilBuffered := &BufferedConn{
		Reader: nil,
		Conn:   c5,
	}

	go func() {
		_, _ = c6.Write([]byte("nil-reader-data"))
	}()

	buf3 := make([]byte, len("nil-reader-data"))
	_, err = io.ReadFull(nilBuffered, buf3)
	if err != nil {
		t.Fatalf("unexpected read error for nil Reader: %v", err)
	}
	if string(buf3) != "nil-reader-data" {
		t.Errorf("expected 'nil-reader-data', got %q", string(buf3))
	}
}

func TestBufferedConn_CloseWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	mock := &mockCloseWriterConn{Conn: c1}
	bConn := &BufferedConn{
		Reader: c1,
		Conn:   mock,
	}

	if err := bConn.CloseWrite(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.closedWrite {
		t.Errorf("expected CloseWrite to be forwarded to mockCloseWriterConn")
	}
}

type mockCloseReaderConn struct {
	net.Conn
	closedRead bool
}

func (m *mockCloseReaderConn) CloseRead() error {
	m.closedRead = true
	return nil
}

func TestBufferedConn_CloseRead(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	mock := &mockCloseReaderConn{Conn: c1}
	bConn := &BufferedConn{
		Reader: c1,
		Conn:   mock,
	}

	if err := bConn.CloseRead(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.closedRead {
		t.Errorf("expected CloseRead to be forwarded to mockCloseReaderConn")
	}
}

// ── Bug #12 (Round 2): Proxy half-close must not call dst.Close() ──

func TestProxy_HalfCloseNoCloseWriter(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyUpstream, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyUpstream.Close()
	defer upstreamConn.Close()

	done := make(chan ProxyResult, 1)
	go func() {
		done <- Proxy(proxyClient, proxyUpstream)
	}()

	clientMsg := []byte("ping")
	upstreamResponse := []byte("pong response from upstream server")

	go func() {
		// Read client ping, then close read on clientConn
		buf := make([]byte, len(clientMsg))
		_, _ = io.ReadFull(upstreamConn, buf)

		// Wait briefly to simulate server processing time while client side is closing
		time.Sleep(20 * time.Millisecond)

		// Write response back to client
		_, _ = upstreamConn.Write(upstreamResponse)
		_ = upstreamConn.Close()
	}()

	// Client writes ping and then closes its connection to trigger half-close in proxy
	_, _ = clientConn.Write(clientMsg)

	// In the old buggy code, clientConn's finish triggered proxyUpstream.Close(),
	// terminating upstreamConn before it could send its response.
	readBuf := make([]byte, len(upstreamResponse))
	_, err := io.ReadFull(clientConn, readBuf)
	if err != nil {
		t.Fatalf("failed to read response from upstream through proxy: %v", err)
	}
	_ = clientConn.Close()

	if !bytes.Equal(readBuf, upstreamResponse) {
		t.Errorf("expected %q, got %q", string(upstreamResponse), string(readBuf))
	}

	select {
	case res := <-done:
		if res.BytesIn != int64(len(clientMsg)) {
			t.Errorf("expected BytesIn=%d, got %d", len(clientMsg), res.BytesIn)
		}
		if res.BytesOut != int64(len(upstreamResponse)) {
			t.Errorf("expected BytesOut=%d, got %d", len(upstreamResponse), res.BytesOut)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy timed out waiting for completion")
	}
}

func TestBufferedConn_EmptyReader(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	bConn := &BufferedConn{
		Reader: bytes.NewReader(nil),
		Conn:   c1,
	}

	go func() {
		_, _ = c2.Write([]byte("direct-from-conn"))
	}()

	buf := make([]byte, 16)
	n, err := bConn.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error reading through empty reader: %v", err)
	}
	if string(buf[:n]) != "direct-from-conn" {
		t.Errorf("expected 'direct-from-conn', got %q", string(buf[:n]))
	}
	if bConn.Reader != nil {
		t.Errorf("expected Reader to be nil after EOF exhaustion")
	}
}

func TestProxy_LargeTransfer(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyUpstream, upstreamConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyUpstream.Close()
	defer upstreamConn.Close()

	done := make(chan ProxyResult, 1)
	go func() {
		done <- Proxy(proxyClient, proxyUpstream)
	}()

	chunkSize := 1024
	totalChunks := 10
	payload := bytes.Repeat([]byte("A"), chunkSize*totalChunks)

	go func() {
		for i := 0; i < totalChunks; i++ {
			_, _ = clientConn.Write(payload[i*chunkSize : (i+1)*chunkSize])
		}
		_ = clientConn.Close()
	}()

	received := make([]byte, len(payload))
	n, err := io.ReadFull(upstreamConn, received)
	if err != nil {
		t.Fatalf("failed reading large transfer: %v", err)
	}
	if n != len(payload) {
		t.Errorf("expected %d bytes, got %d", len(payload), n)
	}
	_ = upstreamConn.Close()

	res := <-done
	if res.BytesIn != int64(len(payload)) {
		t.Errorf("expected BytesIn=%d, got %d", len(payload), res.BytesIn)
	}
}
