package sdk

import "net"

// UDPPacket represents a single datagram in transit, in either direction.
type UDPPacket struct {
	// Payload is the raw datagram bytes. Inspectors may mutate this slice in-place
	// to rewrite the packet before it is forwarded.
	Payload []byte

	// ClientAddr is the source address of the original client (never nil).
	ClientAddr *net.UDPAddr

	// IsReply is true when the packet is travelling upstream → client.
	IsReply bool
}

// UDPVerdict is the decision an inspector returns for a single datagram.
type UDPVerdict int

const (
	// UDPVerdictAllow forwards the datagram (after any payload mutation).
	UDPVerdictAllow UDPVerdict = iota

	// UDPVerdictDrop silently discards the datagram.
	UDPVerdictDrop

	// UDPVerdictReject attempts to send a protocol-level refusal back to the
	// client (best-effort; not all protocols support this).
	UDPVerdictReject
)

// UDPInspector is implemented by protocol-aware UDP session handlers (e.g. DNS, QUIC).
//
// One UDPInspector is created per unique client address via UDPPlugin.CreateUDPInspector.
// All methods must be safe for concurrent calls from multiple goroutines.
type UDPInspector interface {
	// InspectPacket is called for every datagram in both directions.
	// It may mutate pkt.Payload in-place to rewrite the packet content.
	// Returns the verdict, a human-readable reason (used in security events), and
	// any fatal error that should terminate the session.
	InspectPacket(ctx Context, pkt *UDPPacket) (verdict UDPVerdict, reason string, err error)

	// Close is called when the session expires or the daemon is shutting down.
	Close() error
}

// UDPPlugin extends the Plugin interface with the ability to create per-session
// UDP inspectors for datagram-level protocol inspection.
//
// A single plugin struct may implement both Plugin (for TCP) and UDPPlugin (for UDP),
// or just one of them. The engine uses a type assertion to check for UDPPlugin support
// at dispatch time — no changes to the Plugin interface or registry are required.
//
// Example: a DNS plugin implements both Plugin (DNS-over-TCP) and UDPPlugin (DNS-over-UDP).
type UDPPlugin interface {
	// UDPManifest returns the plugin's identity and supported UDP protocols.
	// Implementations may return the same Manifest as Plugin.Manifest().
	UDPManifest() Manifest

	// CreateUDPInspector creates a new inspector for a UDP session.
	// A fresh inspector is created for each unique client address on first packet.
	// config is the service-level plugin_config map.
	CreateUDPInspector(config map[string]any) (UDPInspector, error)
}
