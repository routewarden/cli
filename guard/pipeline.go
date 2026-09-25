package guard

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/routewarden/cli/dashboard"
	"github.com/routewarden/cli/guard/protocol"
)

// Pipeline processes a single accepted TCP connection through all
// policy stages and either proxies it or applies a response action.
type Pipeline struct {
	cfg      *Config
	banlist  *BanList
	failures *FailureTracker
	limiter  *RateLimiter
	bus      *EventBus
}

// NewPipeline creates a Pipeline wired to the shared daemon state.
func NewPipeline(cfg *Config, bl *BanList, ft *FailureTracker, rl *RateLimiter, bus *EventBus) *Pipeline {
	return &Pipeline{cfg: cfg, banlist: bl, failures: ft, limiter: rl, bus: bus}
}

// Handle runs the full 8-stage pipeline for an accepted connection.
func (p *Pipeline) Handle(ctx context.Context, conn net.Conn, svc *ServiceConfig) {
	defer conn.Close()

	start := time.Now()
	clientIP := parseClientIP(conn.RemoteAddr().String())

	// Stage 1 — resolve GeoIP (non-blocking, best-effort)
	geo := dashboard.LookupIP(clientIP)

	ev := GuardEvent{
		Type:         "guard_event",
		Timestamp:    start,
		ClientIP:     clientIP,
		Service:      svc.Name,
		Protocol:     svc.Protocol,
		ListenPort:   listenPort(svc.Listen),
		UpstreamAddr: svc.Upstream,
		Source:       "guard:" + svc.Name,
		CountryCode:  geo.CountryCode,
		CountryName:  geo.CountryName,
		FlagEmoji:    geo.FlagEmoji,
		ISP:          geo.ISP,
		ASN:          geo.AS,
	}

	emit := func(action, reason, mode string) {
		ev.Action = action
		ev.Reason = reason
		ev.ResponseMode = mode
		ev.DurationMs = time.Since(start).Milliseconds()
		p.bus.Publish(ev)
	}

	// Stage 2 — banlist check
	if banned, reason := p.banlist.IsBanned(clientIP); banned {
		emit("BLOCK", "banned: "+reason, "drop")
		applyResponse(conn, svc, "drop", "")
		return
	}

	// Stage 3 — CIDR allowlist (per-service then global)
	allowedIPs := append(svc.AllowedIPs, p.cfg.Global.AllowedIPs...)
	if len(allowedIPs) > 0 && !ipInList(clientIP, allowedIPs) {
		emit("BLOCK", "not in allowlist", "reject")
		applyResponse(conn, svc, svc.Response.Mode, svc.Response.RejectMessage)
		return
	}

	// Stage 4 — explicit blocklist
	blockedIPs := append(svc.BlockedIPs, p.cfg.Global.BlockedIPs...)
	if ipInList(clientIP, blockedIPs) {
		emit("BLOCK", "blocked IP", "drop")
		applyResponse(conn, svc, "drop", "")
		return
	}

	// Stage 5 — geo-block
	blockCountries := append(svc.BlockCountries, p.cfg.Global.BlockCountries...)
	if len(blockCountries) > 0 && geo.CountryCode != "" && !geo.IsPrivate {
		for _, cc := range blockCountries {
			if strings.EqualFold(cc, geo.CountryCode) {
				emit("BLOCK", "geo-blocked country: "+geo.CountryCode, "reject")
				applyResponse(conn, svc, svc.Response.Mode, svc.Response.RejectMessage)
				return
			}
		}
	}

	// Stage 6 — rate limiting
	if !p.limiter.AllowConnection(clientIP, svc.RateLimit.ConnectionsPerMinute) {
		emit("BLOCK", "rate limit exceeded", "reject")
		applyResponse(conn, svc, svc.Response.Mode, svc.Response.RejectMessage)
		return
	}

	// Stage 7 — protocol-level inspection + proxy
	result, blocked, blockReason := p.proxy(ctx, conn, svc, clientIP, geo)
	if blocked {
		emit("BLOCK", blockReason, svc.Response.Mode)
		return
	}

	ev.BytesIn = result.BytesIn
	ev.BytesOut = result.BytesOut
	emit("ALLOW", "", "")
}

// proxy opens the upstream connection and runs the appropriate protocol
// inspector + bidirectional proxy. Returns (result, wasBlocked, reason).
func (p *Pipeline) proxy(
	ctx context.Context,
	client net.Conn,
	svc *ServiceConfig,
	clientIP string,
	geo dashboard.GeoResult,
) (protocol.ProxyResult, bool, string) {

	upstream, err := protocol.DialUpstream(svc.Upstream)
	if err != nil {
		return protocol.ProxyResult{}, true, "upstream unreachable: " + err.Error()
	}
	defer upstream.Close()

	switch strings.ToLower(svc.Protocol) {
	case "ssh":
		return p.proxySSH(ctx, client, upstream, svc, clientIP)
	default:
		// Generic TCP: pure bidirectional proxy
		res := protocol.Proxy(client, upstream)
		return res, false, ""
	}
}

// proxySSH handles the SSH-specific inspection path.
func (p *Pipeline) proxySSH(
	ctx context.Context,
	client, upstream net.Conn,
	svc *ServiceConfig,
	clientIP string,
) (protocol.ProxyResult, bool, string) {

	insp := protocol.SSHInspector{}
	br, result := insp.Inspect(client)

	if !result.Valid {
		protocol.RejectSSH(client, "invalid SSH banner")
		return protocol.ProxyResult{}, true, "invalid SSH banner"
	}
	if result.IsSSH1 {
		protocol.RejectSSH1(client)
		return protocol.ProxyResult{}, true, "SSH-1.x rejected"
	}

	// Re-inject the peeked banner bytes back through the bufio.Reader
	// by creating a multi-reader that drains the buffer then reads raw conn.
	clientWithBuf := &bufferedConn{Reader: io.MultiReader(br, client), Conn: client}

	banThreshold := svc.EffectiveBanAfterFailures(&p.cfg.Global)
	banDur := time.Duration(svc.EffectiveBanDurationSeconds(&p.cfg.Global)) * time.Second
	maxAuthFail := svc.MaxAuthFailures
	if maxAuthFail <= 0 {
		maxAuthFail = banThreshold
	}

	authFails := 0
	monitor := protocol.NewSSHAuthMonitor(func() {
		authFails++
		p.failures.Record(clientIP, svc.Name, "ssh auth failure",
			banThreshold, banDur)
		if maxAuthFail > 0 && authFails >= maxAuthFail {
			client.Close()
		}
	})

	wrappedUpstream := monitor.WrapUpstream(upstream)
	res := protocol.Proxy(clientWithBuf, wrappedUpstream)
	return res, false, ""
}

// applyResponse closes the connection with the appropriate protocol-level
// rejection message based on the configured response mode.
func applyResponse(conn net.Conn, svc *ServiceConfig, mode, msg string) {
	switch mode {
	case "tarpit":
		tarpitMs := svc.Response.TarpitMs
		if tarpitMs <= 0 {
			tarpitMs = 5000
		}
		time.Sleep(time.Duration(tarpitMs) * time.Millisecond)
		conn.Close()
	case "silent":
		// Hold open, do nothing — connection times out on the client side
		time.Sleep(24 * time.Hour)
		conn.Close()
	default: // "drop", "reject", ""
		if msg != "" {
			conn.Write([]byte(msg + "\r\n"))
		}
		conn.Close()
	}
}

// ipInList checks if ip matches any entry in the list (supports CIDR and single IPs).
func ipInList(ip string, list []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, entry := range list {
		if strings.Contains(entry, "/") {
			_, cidr, err := net.ParseCIDR(entry)
			if err == nil && cidr.Contains(parsed) {
				return true
			}
		} else if net.ParseIP(entry) != nil && entry == ip {
			return true
		}
	}
	return false
}

// listenPort parses the port number from an address like ":2222" or "0.0.0.0:2222".
func listenPort(addr string) int {
	var port int
	fmt.Sscanf(addr, ":%d", &port)
	if port == 0 {
		parts := strings.SplitN(addr, ":", 2)
		if len(parts) == 2 {
			fmt.Sscanf(parts[1], "%d", &port)
		}
	}
	return port
}

// bufferedConn combines a bufio.Reader (that may have peeked data) with
// the underlying net.Conn so that it satisfies net.Conn for io.Copy.
type bufferedConn struct {
	io.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.Reader.Read(p)
}
