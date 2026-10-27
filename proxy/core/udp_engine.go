package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/routewarden/cli/proxy/config"
	"github.com/routewarden/cli/proxy/geoip"
	"github.com/routewarden/cli/proxy/plugins"
	"github.com/routewarden/cli/proxy/plugins/sdk"
)

const defaultUDPReadBufSize = 65535 // max UDP datagram size

// serveUDPService is the UDP analogue of serveService.
// A single goroutine owns the listen socket and dispatches each received datagram
// to handleUDPPacket in its own goroutine for parallel processing.
func (d *Daemon) serveUDPService(ctx context.Context, conn *net.UDPConn, svc config.ServiceConfig) {
	defer d.wg.Done()
	defer conn.Close()

	timeout := 30 * time.Second
	if svc.UDP.SessionTimeout.Duration() > 0 {
		timeout = svc.UDP.SessionTimeout.Duration()
	}
	table := NewUDPSessionTable(timeout)
	defer table.Close()

	bufSize := defaultUDPReadBufSize
	if svc.UDP.ReadBufferSize > 0 {
		bufSize = svc.UDP.ReadBufferSize
	}
	buf := make([]byte, bufSize)

	for {
		// Honour context cancellation on every iteration.
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed") {
					return
				}
				d.oplog.Warn("[%s/udp] ReadFromUDP error (retrying in 100ms): %v", svc.Name, err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		// Drop empty packets
		if n == 0 {
			continue
		}

		// Fast path: drop actively banned IPs synchronously before allocating closure/goroutine
		if d.banlist != nil {
			fastIP := clientAddr.IP.String()
			if v4 := clientAddr.IP.To4(); v4 != nil {
				fastIP = v4.String()
			}
			if _, isBanned := d.banlist.IsBanned(fastIP); isBanned {
				if d.stats != nil {
					d.stats.GetOrCreate(svc.Name).AddBlocked()
				}
				continue
			}
		}

		// Copy datagram before handing off — buf is reused on next iteration.
		payload := make([]byte, n)
		copy(payload, buf[:n])

		go d.handleUDPPacket(ctx, conn, clientAddr, payload, svc, table)
	}
}

// handleUDPPacket applies the full security pipeline to a single inbound datagram,
// then forwards it to the upstream socket (and starts the reply goroutine for new sessions).
func (d *Daemon) handleUDPPacket(
	ctx context.Context,
	listenConn *net.UDPConn,
	clientAddr *net.UDPAddr,
	payload []byte,
	svc config.ServiceConfig,
	table *UDPSessionTable,
) {
	clientIP := clientAddr.IP.String()
	if v4 := clientAddr.IP.To4(); v4 != nil {
		clientIP = v4.String()
	}
	geo := geoip.LookupIP(clientIP)
	start := time.Now()

	st := d.stats.GetOrCreate(svc.Name)

	block := func(reason string) {
		st.ConnAccepted()
		st.ConnClosed()
		st.AddBlocked()
		d.pipeline.emitEvent(&svc, clientIP, geo, "blocked", reason, 0, 0, start)
	}

	emit := func(action, reason string, bytesIn, bytesOut int64) {
		d.pipeline.emitEvent(&svc, clientIP, geo, action, reason, bytesIn, bytesOut, start)
	}

	defer func() {
		if r := recover(); r != nil {
			block(fmt.Sprintf("panic in udp handler: %v", r))
			if d.oplog != nil {
				d.oplog.Error("[PANIC] Recovered in UDP packet handler for %s (%s): %v", svc.Name, clientIP, r)
			} else {
				DefaultLogger().Error("[PANIC] Recovered in UDP packet handler for %s (%s): %v", svc.Name, clientIP, r)
			}
		}
	}()

	// ── Stage 1: Active Banlist ───────────────────────────────────────────
	if ban, isBanned := d.banlist.IsBanned(clientIP); isBanned {
		block(fmt.Sprintf("banned: %s", ban.Reason))
		return // UDP: simply drop — no connection to close
	}

	// ── Stage 2: CrowdSec LAPI Bouncer ───────────────────────────────────
	if d.cfg != nil && d.cfg.CrowdSec.Enabled && d.crowdsec != nil {
		if dec, hasDec := d.crowdsec.Check(clientIP); hasDec {
			if strings.EqualFold(dec.Action, "ban") {
				block(fmt.Sprintf("crowdsec_ban: %s", dec.Scenario))
				return
			}
		}
	}

	// ── Stage 3: CIDR IP Filter ───────────────────────────────────────────
	if d.pipeline.isIPDenied(clientIP, &svc) {
		block("ip_denied")
		return
	}

	if d.pipeline.isASNDenied(clientIP, &svc) {
		block("asn_denied")
		return
	}

	// ── Stage 4: Geo-block ────────────────────────────────────────────────
	if d.pipeline.isCountryBlocked(geo.CountryCode, &svc) {
		block(fmt.Sprintf("country_blocked: %s", geo.CountryCode))
		return
	}

	// ── Stage 5: Rate Limiting ────────────────────────────────────────────
	if cpm := svc.RateLimit.ConnectionsPerMinute; cpm > 0 {
		if !d.limiter.Allow(svc.Name, clientIP, cpm, svc.RateLimit.Burst) {
			block("rate_limit_exceeded")
			return
		}
	}

	// ── Stage 6: MaxSessions guard ────────────────────────────────────────
	if max := svc.UDP.MaxSessions; max > 0 && table.Len() >= max {
		block("udp_max_sessions_exceeded")
		return
	}

	// ── Stage 7: Session Lookup / Creation ───────────────────────────────
	var localAddr net.Addr
	if listenConn != nil {
		localAddr = listenConn.LocalAddr()
	}
	targetUpstream, err := svc.ResolveUpstream(localAddr)
	if err != nil {
		targetUpstream = svc.Upstream
	}

	sessionKey := clientAddr.String()
	session, isNew, err := table.GetOrCreate(sessionKey, func() (*UDPSession, error) {
		upstream, err := dialUDPUpstream(targetUpstream)
		if err != nil {
			return nil, fmt.Errorf("dialing UDP upstream %s: %w", targetUpstream, err)
		}

		var inspector sdk.UDPInspector
		if svc.Protocol != "" && !isStandardUDPProtocol(svc.Protocol) {
			if plug, ok := plugins.Get(svc.Protocol); ok {
				if udpPlug, ok := plug.(sdk.UDPPlugin); ok {
					var inspErr error
					inspector, inspErr = udpPlug.CreateUDPInspector(svc.GetPluginOptions())
					if inspErr != nil {
						d.oplog.Warn("[%s/udp] Failed creating UDPInspector for protocol %q: %v",
							svc.Name, svc.Protocol, inspErr)
					}
				}
			}
		}

		// onClose is intentionally nil here — it will be wired after the session
		// wins the LoadOrStore race to prevent a spurious ConnClosed() decrement
		// if this session loses the race and is immediately discarded.
		return &UDPSession{
			ClientAddr: clientAddr,
			Upstream:   upstream,
			Inspector:  inspector,
		}, nil
	})
	if err != nil {
		block("upstream_connect_failed")
		return
	}

	if isNew {
		// Wire the stats callback now that this session has won the race and
		// is officially owned. ConnAccepted() is called immediately after.
		session.onClose = func() { st.ConnClosed() }
		st.ConnAccepted()

		readBufSize := defaultUDPReadBufSize
		if svc.UDP.ReadBufferSize > 0 {
			readBufSize = svc.UDP.ReadBufferSize
		}
		go d.forwardUDPReplies(ctx, listenConn, session, &svc, table, sessionKey, readBufSize)
	}

	// ── Stage 8: UDPInspector — client → upstream direction ───────────────
	pkt := &sdk.UDPPacket{
		Payload:    payload,
		ClientAddr: clientAddr,
		IsReply:    false,
	}
	if session.Inspector != nil {
		pCtx := &sdk.DefaultContext{
			Ctx:           ctx,
			ServiceName:   svc.Name,
			ClientAddress: clientIP,
			SecurityFunc: func(action, reason string) {
				d.pipeline.emitEvent(&svc, clientIP, geo, action, reason, 0, 0, start)
			},
		}
		verdict, reason, _ := session.Inspector.InspectPacket(pCtx, pkt)
		switch verdict {
		case sdk.UDPVerdictDrop, sdk.UDPVerdictReject:
			st.AddBlocked()
			emit("blocked", reason, 0, 0)
			return
		}
	}

	// ── Stage 9: Forward to Upstream ─────────────────────────────────────
	n, err := session.Upstream.Write(pkt.Payload)
	if err != nil {
		table.Delete(sessionKey)
		st.AddBlocked()
		emit("blocked", fmt.Sprintf("upstream_write_failed: %v", err), 0, 0)
		return
	}

	st.AddAllowed()
	st.AddBytes(int64(n), 0)
	emit("allowed", "udp_forwarded", int64(n), 0)
}

// forwardUDPReplies reads datagrams from the upstream socket and writes them back
// to the original client address on the shared listen socket.
// One goroutine per session; exits when the upstream socket is closed or errors.
func (d *Daemon) forwardUDPReplies(
	ctx context.Context,
	listenConn *net.UDPConn,
	session *UDPSession,
	svc *config.ServiceConfig,
	table *UDPSessionTable,
	sessionKey string,
	bufSize int,
) {
	buf := make([]byte, bufSize)
	clientIP := session.ClientAddr.IP.String()
	geo := geoip.LookupIP(clientIP)

	defer func() {
		if r := recover(); r != nil {
			table.Delete(sessionKey)
			d.oplog.Error("[PANIC] Recovered in UDP reply forwarder for %s (%s): %v", svc.Name, clientIP, r)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			table.Delete(sessionKey)
			return
		default:
		}

		n, _, err := session.Upstream.ReadFrom(buf)
		if err != nil {
			// Upstream closed or session was reaped — exit silently.
			table.Delete(sessionKey)
			return
		}

		session.Touch()

		replyPayload := make([]byte, n)
		copy(replyPayload, buf[:n])

		// Run inspector on the reply direction if configured.
		if session.Inspector != nil {
			pkt := &sdk.UDPPacket{
				Payload:    replyPayload,
				ClientAddr: session.ClientAddr,
				IsReply:    true,
			}
			pCtx := &sdk.DefaultContext{
				Ctx:           ctx,
				ServiceName:   svc.Name,
				ClientAddress: clientIP,
				SecurityFunc: func(action, reason string) {
					d.pipeline.emitEvent(svc, clientIP, geo, action, reason, 0, 0, time.Now())
				},
			}
			verdict, _, _ := session.Inspector.InspectPacket(pCtx, pkt)
			if verdict != sdk.UDPVerdictAllow {
				continue // drop or reject: don't forward this reply
			}
			replyPayload = pkt.Payload // may have been rewritten by inspector
		}

		written, err := listenConn.WriteTo(replyPayload, session.ClientAddr)
		if err != nil {
			table.Delete(sessionKey)
			return
		}

		st := d.stats.GetOrCreate(svc.Name)
		st.AddBytes(0, int64(written))
	}
}

// dialUDPUpstream resolves and dials a UDP upstream address.
func dialUDPUpstream(upstream string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", upstream)
	if err != nil {
		return nil, fmt.Errorf("resolving UDP upstream %q: %w", upstream, err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("dialing UDP upstream %q: %w", upstream, err)
	}
	return conn, nil
}

// isStandardUDPProtocol returns true for protocols handled transparently
// without an inspector (plain UDP passthrough).
func isStandardUDPProtocol(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "udp", "generic", "":
		return true
	default:
		return false
	}
}
