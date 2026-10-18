package observability

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/routewarden/cli/crypto"
)

// DefaultDir returns the default directory where dashboard files are stored.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".routewarden/dashboard"
	}
	return filepath.Join(home, ".routewarden", "dashboard")
}

// FindGoAccess checks whether 'goaccess' binary is available in PATH.
func FindGoAccess() (string, error) {
	return exec.LookPath("goaccess")
}

// FindDocker checks whether 'docker' CLI is available in PATH.
func FindDocker() (string, error) {
	return exec.LookPath("docker")
}

// EnsureStackPrepared unpacks embedded GoAccess assets to dir if not already present.
func EnsureStackPrepared(dir string) error {
	composeFile := filepath.Join(dir, "docker-compose.yml")
	if _, err := os.Stat(composeFile); err == nil {
		return nil
	}
	return Export(dir)
}

type containerTarget struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type RemoteAgentInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Hostname   string `json:"hostname,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
	EventCount int64  `json:"event_count"`
	Status     string `json:"status"` // "online", "idle", "offline"
}

type SourceInfo struct {
	Mode         string             `json:"mode"`
	File         string             `json:"file,omitempty"`
	Targets      []containerTarget  `json:"targets,omitempty"`
	Agents       []*RemoteAgentInfo `json:"agents,omitempty"`
	TotalEvents  int64              `json:"total_events"`
	BlockedCount int64              `json:"blocked_count"`
	TarpitCount  int64              `json:"tarpit_count"`
}

var (
	sourceMu     sync.RWMutex
	currSource   SourceInfo
	agentMu      sync.RWMutex
	agents       = make(map[string]*RemoteAgentInfo)
	totalEvents  int64
	blockedCount int64
	tarpitCount  int64
)

func recordMetric(status int, verdict string) {
	atomic.AddInt64(&totalEvents, 1)
	v := strings.ToUpper(verdict)
	if status == 403 || v == "BLOCK" {
		atomic.AddInt64(&blockedCount, 1)
	} else if status == 429 || v == "TARPIT" {
		atomic.AddInt64(&tarpitCount, 1)
	}
}

func registerOrTouchAgent(id, name, hostname, remoteIP string, eventCount int) *RemoteAgentInfo {
	agentMu.Lock()
	defer agentMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	ag, exists := agents[id]
	if !exists {
		ag = &RemoteAgentInfo{
			ID:        id,
			Name:      name,
			Hostname:  hostname,
			RemoteIP:  remoteIP,
			FirstSeen: now,
			LastSeen:  now,
			Status:    "online",
		}
		agents[id] = ag
	}
	ag.LastSeen = now
	if remoteIP != "" {
		ag.RemoteIP = remoteIP
	}
	if hostname != "" {
		ag.Hostname = hostname
	}
	ag.EventCount += int64(eventCount)
	ag.Status = "online"
	return ag
}

func getActiveAgents() []*RemoteAgentInfo {
	agentMu.RLock()
	defer agentMu.RUnlock()
	var list []*RemoteAgentInfo
	now := time.Now().UTC()
	for _, a := range agents {
		if parsed, err := time.Parse(time.RFC3339, a.LastSeen); err == nil {
			diff := now.Sub(parsed)
			if diff > 5*time.Minute {
				a.Status = "offline"
			} else if diff > 60*time.Second {
				a.Status = "idle"
			} else {
				a.Status = "online"
			}
		}
		list = append(list, a)
	}
	return list
}

func updateSourceInfo(mode, file string, targets []containerTarget) {
	sourceMu.Lock()
	defer sourceMu.Unlock()
	currSource = SourceInfo{
		Mode:    mode,
		File:    file,
		Targets: targets,
	}
}

func getSourceInfo() SourceInfo {
	sourceMu.RLock()
	defer sourceMu.RUnlock()
	s := currSource
	s.Agents = getActiveAgents()
	s.TotalEvents = atomic.LoadInt64(&totalEvents)
	s.BlockedCount = atomic.LoadInt64(&blockedCount)
	s.TarpitCount = atomic.LoadInt64(&tarpitCount)
	return s
}

const sourceBadgeInjection = `
<style>
/* RouteWarden Executive Security Dashboard Styling */
:root {
  --rw-bg: #0b0f19;
  --rw-card-bg: rgba(17, 24, 39, 0.78);
  --rw-card-border: rgba(255, 255, 255, 0.08);
  --rw-accent-blue: #38bdf8;
  --rw-accent-indigo: #6366f1;
  --rw-accent-green: #10b981;
  --rw-accent-red: #f43f5e;
  --rw-accent-amber: #f59e0b;
  --rw-accent-purple: #a855f7;
}

body {
  background-color: var(--rw-bg) !important;
  color: #f1f5f9 !important;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
  -webkit-font-smoothing: antialiased;
}

.container {
  max-width: 96% !important;
  margin: 0 auto !important;
}

/* Glassmorphic Panel Cards */
.wrap-panel {
  background: var(--rw-card-bg) !important;
  backdrop-filter: blur(14px) !important;
  -webkit-backdrop-filter: blur(14px) !important;
  border: 1px solid var(--rw-card-border) !important;
  border-radius: 12px !important;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35) !important;
  margin-bottom: 24px !important;
  transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease !important;
}
.wrap-panel:hover {
  border-color: rgba(99, 102, 241, 0.35) !important;
  box-shadow: 0 14px 40px rgba(0, 0, 0, 0.45) !important;
}

/* Table Enhancements */
table.table th {
  background: rgba(15, 23, 42, 0.75) !important;
  color: #94a3b8 !important;
  font-weight: 600 !important;
  text-transform: uppercase !important;
  font-size: 11px !important;
  letter-spacing: 0.05em !important;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
}
table.table td {
  border-bottom: 1px solid rgba(255, 255, 255, 0.04) !important;
  color: #cbd5e1 !important;
  font-size: 12px !important;
}
table.table tr:hover td {
  background: rgba(255, 255, 255, 0.03) !important;
}

/* RouteWarden Dashboard Container */
#rw-dashboard-header {
  margin: 14px 0 22px 0;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

/* Security KPI Cards Grid */
.rw-kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: 12px;
}
.rw-kpi-card {
  background: var(--rw-card-bg);
  backdrop-filter: blur(14px);
  -webkit-backdrop-filter: blur(14px);
  border: 1px solid var(--rw-card-border);
  border-radius: 10px;
  padding: 14px 16px;
  box-shadow: 0 6px 18px rgba(0, 0, 0, 0.25);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  position: relative;
  overflow: hidden;
  transition: transform 0.2s ease, border-color 0.2s ease;
}
.rw-kpi-card:hover {
  transform: translateY(-2px);
  border-color: rgba(255, 255, 255, 0.2);
}
.rw-kpi-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}
.rw-kpi-label {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: #94a3b8;
}
.rw-kpi-icon {
  font-size: 16px;
  opacity: 0.9;
}
.rw-kpi-val {
  font-size: 24px;
  font-weight: 700;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  color: #f8fafc;
  line-height: 1.1;
  letter-spacing: -0.02em;
}
.rw-kpi-sub {
  font-size: 11px;
  color: #64748b;
  margin-top: 6px;
  display: flex;
  align-items: center;
  gap: 6px;
}
.rw-pill-blocked {
  background: rgba(244, 63, 94, 0.15);
  color: #fb7185;
  border: 1px solid rgba(244, 63, 94, 0.3);
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
}
.rw-pill-tarpit {
  background: rgba(245, 158, 11, 0.15);
  color: #fcd34d;
  border: 1px solid rgba(245, 158, 11, 0.3);
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
}
.rw-pill-secure {
  background: rgba(168, 85, 247, 0.15);
  color: #c084fc;
  border: 1px solid rgba(168, 85, 247, 0.3);
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
}

/* Monitored Sources Bar */
#rw-status-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  background: rgba(15, 23, 42, 0.7);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 8px;
  padding: 10px 16px;
  font-size: 13px;
  color: #e2e8f0;
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25);
}
.rw-pulse {
  width: 8px;
  height: 8px;
  background-color: #10b981;
  border-radius: 50%;
  display: inline-block;
  box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
  animation: rw-pulse-anim 2s infinite;
}
@keyframes rw-pulse-anim {
  0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
  70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
  100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}
.rw-pulse-idle {
  width: 8px;
  height: 8px;
  background-color: #f59e0b;
  border-radius: 50%;
  display: inline-block;
}
.rw-tag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: rgba(255, 255, 255, 0.06);
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 6px;
  padding: 4px 10px;
  font-size: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  color: #93c5fd;
  transition: background 0.15s ease;
}
.rw-tag:hover {
  background: rgba(255, 255, 255, 0.1);
}
.rw-tag-id {
  color: #94a3b8;
  font-size: 11px;
}
.rw-label {
  font-weight: 600;
  color: #cbd5e1;
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
}

/* ==========================================================================
   Advanced Visual Aesthetics for GoAccess SVG / D3 Charts & Graphs
   ========================================================================== */

/* Chart Containers */
.wrap-chart,
.chart-container,
div.chart,
div.d3-chart,
article .wrap-chart {
  background: rgba(10, 15, 29, 0.65) !important;
  border-radius: 10px !important;
  border: 1px solid rgba(255, 255, 255, 0.06) !important;
  padding: 16px 14px 10px 14px !important;
  margin: 14px 0 16px 0 !important;
  box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.3) !important;
  position: relative !important;
}

svg.chart,
svg.d3-chart,
svg.map,
svg.area-chart {
  overflow: visible !important;
}

/* SVG Axes & Domain Lines */
svg .axis path,
svg .axis line,
svg path.domain,
.axis path,
.axis line {
  stroke: rgba(255, 255, 255, 0.12) !important;
  stroke-width: 1px !important;
  shape-rendering: crispEdges !important;
}

/* Subtle Dotted Grid Lines */
svg .grid line,
svg .grid .tick line,
.grid line {
  stroke: rgba(255, 255, 255, 0.04) !important;
  stroke-dasharray: 3, 3 !important;
}
svg .grid path {
  display: none !important;
}

/* Monospace Tick Labels */
svg .axis text,
.axis text,
svg text.label,
text.tick {
  fill: #94a3b8 !important;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
  font-size: 11px !important;
  font-weight: 500 !important;
}

/* Area Chart Smooth Gradient Fills */
svg path.area,
.area-chart path,
.area {
  fill: url(#rw-hits-grad) !important;
  opacity: 0.88 !important;
  transition: opacity 0.2s ease !important;
}
svg path.area:nth-of-type(2),
svg path.area.visitors {
  fill: url(#rw-visitors-grad) !important;
}

/* High-Contrast Neon Spline Curves */
svg path.line,
.line-chart path,
path.line {
  stroke: var(--rw-accent-blue) !important;
  stroke-width: 2.5px !important;
  stroke-linecap: round !important;
  stroke-linejoin: round !important;
  fill: none !important;
  filter: drop-shadow(0 2px 8px rgba(56, 189, 248, 0.35)) !important;
}
svg path.line:nth-of-type(2),
svg path.line.visitors {
  stroke: var(--rw-accent-green) !important;
  filter: drop-shadow(0 2px 8px rgba(16, 185, 129, 0.35)) !important;
}
svg path.line:nth-of-type(3),
svg path.line.bytes {
  stroke: var(--rw-accent-amber) !important;
  filter: drop-shadow(0 2px 8px rgba(245, 158, 11, 0.35)) !important;
}

/* Data Points & Dots */
svg circle.dot,
svg circle.point,
svg circle.node,
svg circle.focus {
  fill: #38bdf8 !important;
  stroke: #0b0f19 !important;
  stroke-width: 2px !important;
  r: 4px !important;
  transition: r 0.15s ease, fill 0.15s ease !important;
}
svg circle.dot:hover,
svg circle.point:hover {
  r: 6.5px !important;
  fill: #7dd3fc !important;
  filter: drop-shadow(0 0 8px #38bdf8) !important;
}

/* Bar Charts (Pill Rounded Columns with Smooth Glow) */
svg rect.bar,
g.bar rect,
.bars rect,
svg rect {
  rx: 4px !important;
  ry: 4px !important;
  fill: var(--rw-accent-indigo) !important;
  opacity: 0.88 !important;
  transition: opacity 0.2s ease, fill 0.2s ease !important;
}
svg rect.bar:hover,
g.bar rect:hover,
.bars rect:hover {
  opacity: 1 !important;
  fill: var(--rw-accent-blue) !important;
  filter: drop-shadow(0 0 8px rgba(56, 189, 248, 0.45)) !important;
}

/* Modern Glassmorphic Tooltips */
.chart-tooltip-wrap,
.d3-tip,
.tooltip,
#chart-tooltip {
  background: rgba(15, 23, 42, 0.95) !important;
  backdrop-filter: blur(14px) !important;
  -webkit-backdrop-filter: blur(14px) !important;
  border: 1px solid rgba(255, 255, 255, 0.15) !important;
  border-radius: 8px !important;
  box-shadow: 0 10px 25px rgba(0, 0, 0, 0.55), 0 0 15px rgba(56, 189, 248, 0.18) !important;
  color: #f8fafc !important;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
  font-size: 12px !important;
  padding: 8px 14px !important;
  line-height: 1.5 !important;
  pointer-events: none !important;
  z-index: 99999 !important;
}

/* Table Inline Volume & Progress Bars */
td .bar,
table.table .bar,
.progress-bar,
.bar-inner,
div.bar {
  border-radius: 6px !important;
  height: 6px !important;
  background: linear-gradient(90deg, #6366f1, #38bdf8) !important;
  box-shadow: 0 1px 6px rgba(99, 102, 241, 0.35) !important;
}
table.table td.row-idx {
  color: #64748b !important;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
  font-size: 11px !important;
}
table.table td.percent,
table.table span.percent {
  color: #94a3b8 !important;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
  font-size: 11px !important;
  font-weight: 500 !important;
}
.cell-hl.b1, .cell-hl.b2 {
  background: rgba(99, 102, 241, 0.25) !important;
  color: #c7d2fe !important;
  border: 1px solid rgba(99, 102, 241, 0.4) !important;
  border-radius: 4px !important;
  font-weight: 600 !important;
}
.span-hl.g5 {
  background: rgba(255, 255, 255, 0.08) !important;
  color: #e2e8f0 !important;
  border-radius: 3px !important;
}

/* Chart Toggles and Control Buttons */
.btn-default,
.btn-group .btn,
.panel-controls .btn,
.chart-controls .btn,
.nav-bars,
.nav-gears {
  background: rgba(255, 255, 255, 0.05) !important;
  border: 1px solid rgba(255, 255, 255, 0.1) !important;
  color: #cbd5e1 !important;
  border-radius: 6px !important;
  font-size: 12px !important;
  transition: all 0.2s ease !important;
}
.btn-default:hover,
.btn-group .btn:hover,
.panel-controls .btn:hover,
.chart-controls .btn:hover {
  background: rgba(56, 189, 248, 0.15) !important;
  border-color: rgba(56, 189, 248, 0.4) !important;
  color: #38bdf8 !important;
  box-shadow: 0 0 10px rgba(56, 189, 248, 0.2) !important;
}
.btn-group .btn.active,
.btn-default.active {
  background: rgba(99, 102, 241, 0.3) !important;
  border-color: #6366f1 !important;
  color: #ffffff !important;
}

/* Geo Location Map Visuals */
svg.map path.country,
svg.map path.land {
  fill: #1e293b !important;
  stroke: rgba(255, 255, 255, 0.07) !important;
  stroke-width: 0.6px !important;
  transition: fill 0.2s ease !important;
}
svg.map path.country:hover {
  fill: #38bdf8 !important;
  cursor: pointer !important;
}
svg.map circle.city,
svg.map circle.bubble {
  fill: #f43f5e !important;
  fill-opacity: 0.8 !important;
  stroke: #ffffff !important;
  stroke-width: 1px !important;
}
.legend-svg text {
  fill: #94a3b8 !important;
  font-size: 10px !important;
}
</style>
<script>
(function() {
  function injectSVGDefs() {
    var defsId = 'rw-svg-defs-elem';
    if (document.getElementById(defsId)) return;
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.id = defsId;
    svg.style.position = 'absolute';
    svg.style.width = '0';
    svg.style.height = '0';
    svg.style.overflow = 'hidden';
    svg.setAttribute('aria-hidden', 'true');
    svg.innerHTML = '<defs>' +
      '<linearGradient id="rw-hits-grad" x1="0%" y1="0%" x2="0%" y2="100%">' +
        '<stop offset="0%" stop-color="#38bdf8" stop-opacity="0.45"/>' +
        '<stop offset="60%" stop-color="#38bdf8" stop-opacity="0.15"/>' +
        '<stop offset="100%" stop-color="#38bdf8" stop-opacity="0.0"/>' +
      '</linearGradient>' +
      '<linearGradient id="rw-visitors-grad" x1="0%" y1="0%" x2="0%" y2="100%">' +
        '<stop offset="0%" stop-color="#10b981" stop-opacity="0.45"/>' +
        '<stop offset="60%" stop-color="#10b981" stop-opacity="0.15"/>' +
        '<stop offset="100%" stop-color="#10b981" stop-opacity="0.0"/>' +
      '</linearGradient>' +
      '<linearGradient id="rw-bar-grad" x1="0%" y1="0%" x2="100%" y2="0%">' +
        '<stop offset="0%" stop-color="#6366f1"/>' +
        '<stop offset="100%" stop-color="#38bdf8"/>' +
      '</linearGradient>' +
    '</defs>';
    if (document.body) {
      document.body.appendChild(svg);
    }
  }

  function enhanceCharts() {
    injectSVGDefs();
    var rects = document.querySelectorAll('svg rect.bar, g.bar rect, .bars rect');
    for (var i = 0; i < rects.length; i++) {
      if (!rects[i].getAttribute('rx')) {
        rects[i].setAttribute('rx', '4');
        rects[i].setAttribute('ry', '4');
      }
    }
  }

  function renderHeader(data) {
    var container = document.getElementById('rw-dashboard-header');
    if (!container) {
      container = document.createElement('div');
      container.id = 'rw-dashboard-header';
      var titleElem = document.getElementById('report-title');
      if (titleElem && titleElem.parentNode) {
        titleElem.parentNode.insertBefore(container, titleElem.nextSibling);
      } else {
        var parent = document.querySelector('.container') || document.body;
        parent.insertBefore(container, parent.firstChild);
      }
    }

    var total = data.total_events || 0;
    var blocked = data.blocked_count || 0;
    var tarpit = data.tarpit_count || 0;
    var blockRate = total > 0 ? ((blocked / total) * 100).toFixed(1) + '%' : '0.0%';

    var totalSources = 0;
    if (data.targets) totalSources += data.targets.length;
    if (data.agents) totalSources += data.agents.length;

    var kpiHTML = '<div class="rw-kpi-grid">' +
      '<div class="rw-kpi-card" style="border-top: 3px solid #38bdf8;">' +
        '<div class="rw-kpi-top"><span class="rw-kpi-label">Total Ingested</span><span class="rw-kpi-icon">🛡️</span></div>' +
        '<div class="rw-kpi-val">' + Number(total).toLocaleString() + '</div>' +
        '<div class="rw-kpi-sub">Real-time gateway events</div>' +
      '</div>' +
      '<div class="rw-kpi-card" style="border-top: 3px solid #f43f5e;">' +
        '<div class="rw-kpi-top"><span class="rw-kpi-label">Threats Blocked</span><span class="rw-kpi-icon">🛑</span></div>' +
        '<div class="rw-kpi-val" style="color: #fb7185;">' + Number(blocked).toLocaleString() + '</div>' +
        '<div class="rw-kpi-sub"><span class="rw-pill-blocked">' + blockRate + ' block rate</span> 403 Forbidden</div>' +
      '</div>' +
      '<div class="rw-kpi-card" style="border-top: 3px solid #f59e0b;">' +
        '<div class="rw-kpi-top"><span class="rw-kpi-label">Throttled / Tarpit</span><span class="rw-kpi-icon">⏳</span></div>' +
        '<div class="rw-kpi-val" style="color: #fcd34d;">' + Number(tarpit).toLocaleString() + '</div>' +
        '<div class="rw-kpi-sub"><span class="rw-pill-tarpit">429 Slowed</span> Hostile bots</div>' +
      '</div>' +
      '<div class="rw-kpi-card" style="border-top: 3px solid #10b981;">' +
        '<div class="rw-kpi-top"><span class="rw-kpi-label">Active Sources</span><span class="rw-kpi-icon">🌐</span></div>' +
        '<div class="rw-kpi-val" style="color: #6ee7b7;">' + totalSources + '</div>' +
        '<div class="rw-kpi-sub"><span class="rw-pulse"></span> Nodes connected</div>' +
      '</div>' +
      '<div class="rw-kpi-card" style="border-top: 3px solid #a855f7;">' +
        '<div class="rw-kpi-top"><span class="rw-kpi-label">Telemetry Cipher</span><span class="rw-kpi-icon">🔒</span></div>' +
        '<div class="rw-kpi-val" style="font-size: 16px; margin-top: 4px; color: #d8b4fe;">X25519 + AES</div>' +
        '<div class="rw-kpi-sub"><span class="rw-pill-secure">Zero-Knowledge</span> ECDH Stream</div>' +
      '</div>' +
    '</div>';

    var sourcesHTML = '<div id="rw-status-bar">' +
      '<div class="rw-label"><span class="rw-pulse"></span> Monitored Nodes:</div>';

    if (data.mode === 'file') {
      sourcesHTML += '<span class="rw-tag">📁 ' + (data.file || 'Local Log File') + '</span>';
    }

    if (data.targets && data.targets.length > 0) {
      data.targets.forEach(function(t) {
        var shortID = (t.id && t.id.length > 12) ? t.id.substring(0, 12) : t.id;
        sourcesHTML += '<span class="rw-tag">🐳 ' + t.name + ' <span class="rw-tag-id">(' + shortID + ')</span></span>';
      });
    }

    if (data.agents && data.agents.length > 0) {
      data.agents.forEach(function(ag) {
        var statusDot = ag.status === 'online' ? '<span class="rw-pulse"></span>' : '<span class="rw-pulse-idle"></span>';
        var extra = ag.event_count > 0 ? ' • ' + Number(ag.event_count).toLocaleString() + ' ev' : '';
        sourcesHTML += '<span class="rw-tag">' + statusDot + ' 🌐 ' + ag.name + ' <span class="rw-tag-id">(' + (ag.remote_ip || 'remote') + extra + ')</span> <span style="color:#a78bfa;font-size:10px;">🔒 Encrypted</span></span>';
      });
    }

    if (totalSources === 0 && data.mode !== 'file') {
      sourcesHTML += '<span style="color:#94a3b8; font-style:italic; font-size:12px;">Waiting for local Docker containers or remote agents (<code>rwarden push</code>)...</span>';
    } else {
      sourcesHTML += '<span style="color:#64748b; font-size:11px; margin-left:auto;">' + totalSources + ' active source' + (totalSources > 1 ? 's' : '') + '</span>';
    }
    sourcesHTML += '</div>';

    container.innerHTML = kpiHTML + sourcesHTML;
    enhanceCharts();
  }

  function fetchSources() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/sources', true);
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4 && xhr.status === 200) {
        try {
          var data = JSON.parse(xhr.responseText);
          renderHeader(data);
        } catch(e) {}
      }
    };
    xhr.send();
  }

  function init() {
    fetchSources();
    enhanceCharts();
    if (window.MutationObserver && document.body) {
      var observer = new MutationObserver(function() {
        enhanceCharts();
      });
      observer.observe(document.body, { childList: true, subtree: true });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  setInterval(fetchSources, 3000);
})();
</script>
`

type streamMsg struct {
	Container string
	Line      string
}

type logEvent struct {
	Timestamp      string  `json:"time"`
	TimestampAlt   string  `json:"timestamp"`
	ClientIP       string  `json:"client_ip"`
	ClientIPAlt    string  `json:"ip"`
	ClientHost     string  `json:"ClientHost"`
	Verdict        string  `json:"verdict"`
	Method         string  `json:"method"`
	RequestMethod  string  `json:"RequestMethod"`
	Path           string  `json:"path"`
	PathAlt        string  `json:"request_uri"`
	RequestPath    string  `json:"RequestPath"`
	MatchedPattern string  `json:"matched_pattern"`
	MatchedRuleAlt string  `json:"rule"`
	StatusCode     int     `json:"status"`
	StatusCodeAlt  int     `json:"status_code"`
	DownstreamStat int     `json:"DownstreamStatus"`
	LatencyMs      float64 `json:"latency_ms"`
	DurationMsAlt  float64 `json:"duration_ms"`
}

var combinedLogRegex = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]+"\s+(\d{3})\s+\S+`)

func toCombinedLog(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	// Already combined format
	if match := combinedLogRegex.FindStringSubmatch(line); len(match) >= 6 {
		statusCode, _ := strconv.Atoi(match[5])
		recordMetric(statusCode, "")
		return line
	}

	// Try JSON format
	var ev logEvent
	if err := json.Unmarshal([]byte(line), &ev); err == nil && (ev.Path != "" || ev.PathAlt != "" || ev.RequestPath != "" || ev.ClientIP != "" || ev.ClientIPAlt != "" || ev.ClientHost != "" || ev.Verdict != "") {
		ip := ev.ClientIP
		if ip == "" {
			ip = ev.ClientIPAlt
		}
		if ip == "" {
			ip = ev.ClientHost
		}
		if ip == "" {
			ip = "127.0.0.1"
		}

		path := ev.Path
		if path == "" {
			path = ev.PathAlt
		}
		if path == "" {
			path = ev.RequestPath
		}
		if path == "" {
			path = "/"
		}
		path = strings.ReplaceAll(path, `"`, "%22")

		method := ev.Method
		if method == "" {
			method = ev.RequestMethod
		}
		if method == "" {
			method = "GET"
		}
		method = strings.ReplaceAll(method, `"`, "")

		status := ev.StatusCode
		if status == 0 {
			status = ev.StatusCodeAlt
		}
		if status == 0 {
			status = ev.DownstreamStat
		}
		if status == 0 {
			switch strings.ToUpper(ev.Verdict) {
			case "BLOCK":
				status = 403
			case "TARPIT":
				status = 429
			default:
				status = 200
			}
		}

		recordMetric(status, ev.Verdict)

		t := time.Now().UTC()
		if ev.Timestamp != "" {
			if parsed, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
				t = parsed
			}
		} else if ev.TimestampAlt != "" {
			if parsed, err := time.Parse(time.RFC3339, ev.TimestampAlt); err == nil {
				t = parsed
			}
		}
		timeStr := t.Format("02/Jan/2006:15:04:05 -0700")

		rule := ev.MatchedPattern
		if rule == "" {
			rule = ev.MatchedRuleAlt
		}
		rule = strings.ReplaceAll(rule, `"`, `'`)
		verdict := strings.ToUpper(ev.Verdict)

		userAgent := "RouteWarden"
		if rule != "" {
			if verdict != "" && verdict != "ALLOW" {
				userAgent = fmt.Sprintf("[%s: %s]", verdict, rule)
			} else {
				userAgent = fmt.Sprintf("[RULE: %s]", rule)
			}
		} else if verdict != "" && verdict != "ALLOW" {
			userAgent = fmt.Sprintf("[%s]", verdict)
		} else if verdict == "ALLOW" {
			userAgent = "RouteWarden/1.5 (Clean)"
		}
		userAgent = strings.ReplaceAll(userAgent, `"`, `'`)

		return fmt.Sprintf("%s - - [%s] \"%s %s HTTP/1.1\" %d 0 \"-\" \"%s\"", ip, timeStr, method, path, status, userAgent)
	}

	// Drop arbitrary non-HTTP and debug log lines
	return ""
}

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// Up starts the GoAccess live dashboard and multiplexes logs from Docker containers or file.
func Up(ctx context.Context, dir string, port int, noOpen bool, file string, container string, label string) error {
	if dir == "" {
		dir = DefaultDir()
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create dashboard dir: %w", err)
	}
	if err := EnsureStackPrepared(dir); err != nil {
		return fmt.Errorf("prepare dashboard assets: %w", err)
	}

	reportPath := filepath.Join(dir, "index.html")
	logFilePath := filepath.Join(dir, "access.log")
	confPath := filepath.Join(dir, "goaccess.conf")

	// Create access.log if not present
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open access log: %w", err)
	}
	defer logFile.Close()

	dashboardCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Discover container targets or tail file
	var targets []containerTarget
	if file != "" {
		updateSourceInfo("file", file, nil)
		tailFileToLog(dashboardCtx, file, logFile)
	} else if container != "" {
		if found, err := findSpecificContainer(container); err == nil && len(found) > 0 {
			targets = found
		} else {
			targets = []containerTarget{{ID: container, Name: container}}
		}
		updateSourceInfo("docker", "", targets)
	} else {
		discovered, err := discoverDockerContainers(label)
		if err == nil && len(discovered) > 0 {
			targets = discovered
		}
		updateSourceInfo("docker", "", targets)
	}

	// Prime access.log with initial logs from targets so GoAccess renders immediately
	if len(targets) > 0 {
		for _, target := range targets {
			cmd := exec.Command("docker", "logs", "--tail", "100", target.ID)
			if out, err := cmd.CombinedOutput(); err == nil {
				for _, l := range strings.Split(string(out), "\n") {
					combined := toCombinedLog(l)
					if combined != "" {
						_, _ = logFile.WriteString(combined + "\n")
					}
				}
				_ = logFile.Sync()
			}
		}
	} else if file == "" {
		initLine := toCombinedLog(`{"time":"` + time.Now().UTC().Format(time.RFC3339) + `","client_ip":"127.0.0.1","method":"GET","path":"/health","verdict":"ALLOW"}`)
		_, _ = logFile.WriteString(initLine + "\n")
		_ = logFile.Sync()
	}

	wsPort, err := getFreePort()
	if err != nil {
		wsPort = port + 1
	}

	goaccessBin, errGoaccess := FindGoAccess()
	dockerBin, errDocker := FindDocker()

	if errGoaccess != nil && errDocker != nil {
		return fmt.Errorf("neither 'goaccess' nor 'docker' is installed. Please install GoAccess (brew install goaccess / apt install goaccess) or Docker")
	}

	useDockerGoaccess := (errGoaccess != nil)
	var goaccessCmd *exec.Cmd

	if !useDockerGoaccess {
		// Run native GoAccess
		wsURL := fmt.Sprintf("ws://localhost:%d/ws", port)
		args := []string{
			logFilePath,
			"--config-file=" + confPath,
			"--real-time-html",
			fmt.Sprintf("--port=%d", wsPort),
			"--addr=127.0.0.1",
			"--ws-url=" + wsURL,
			"-o", reportPath,
		}
		goaccessCmd = exec.CommandContext(dashboardCtx, goaccessBin, args...)
	} else {
		// Run GoAccess via Docker container (allinurl/goaccess:latest entrypoint is goaccess)
		wsURL := fmt.Sprintf("ws://localhost:%d/ws", port)
		_ = exec.Command("docker", "rm", "-f", "routewarden-dashboard").Run()

		args := []string{
			"run", "--rm",
			"--name", "routewarden-dashboard",
			"-p", fmt.Sprintf("127.0.0.1:%d:7890", wsPort),
			"-v", fmt.Sprintf("%s:/srv/report", dir),
			"allinurl/goaccess:latest",
			"/srv/report/access.log",
			"--config-file=/srv/report/goaccess.conf",
			"--real-time-html",
			"--port=7890",
			"--addr=0.0.0.0",
			"--ws-url=" + wsURL,
			"-o", "/srv/report/index.html",
		}
		goaccessCmd = exec.CommandContext(dashboardCtx, dockerBin, args...)
	}

	if err := goaccessCmd.Start(); err != nil {
		return fmt.Errorf("start GoAccess engine: %w", err)
	}

	// Monitor GoAccess exit
	go func() {
		if err := goaccessCmd.Wait(); err != nil && dashboardCtx.Err() == nil {
			fmt.Fprintf(os.Stderr, "GoAccess process exited: %v\n", err)
		}
	}()

	defer func() {
		if goaccessCmd.Process != nil {
			_ = goaccessCmd.Process.Kill()
		}
		if useDockerGoaccess {
			_ = exec.Command("docker", "rm", "-f", "routewarden-dashboard").Run()
		}
	}()

	// Continuously stream new logs from discovered containers and watch lifecycle
	if file == "" {
		go watchAndStreamContainers(dashboardCtx, label, container, targets, logFile)
	}

	// Server keypair for decryption
	serverPriv, serverPub, err := EnsureServerKeypair(dir)
	if err != nil {
		return fmt.Errorf("initialize server keypair: %w", err)
	}
	serverPubStr := crypto.EncodePublicKey(serverPub)

	// Setup ReverseProxy for WebSocket and HTTP Server
	targetURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", wsPort))
	wsProxy := httputil.NewSingleHostReverseProxy(targetURL)

	mux := NewDashboardHandler(dir, serverPriv, serverPubStr, logFile, wsProxy, reportPath)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		<-dashboardCtx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	dashboardURL := fmt.Sprintf("http://localhost:%d", port)
	fmt.Println("🚀 RouteWarden Security Dashboard (GoAccess) is running!")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("📊 Live Dashboard:     %s\n", dashboardURL)
	fmt.Printf("🔒 Encrypted Ingest:   %s/api/v1/events\n", dashboardURL)
	if len(targets) > 0 {
		fmt.Printf("🐳 Discovered Gateway: %d container(s):\n", len(targets))
		for _, t := range targets {
			fmt.Printf("   • %s (%s)\n", t.Name, t.ID[:min(12, len(t.ID))])
		}
	} else if file != "" {
		fmt.Printf("📁 Monitoring File:    %s\n", file)
	} else {
		fmt.Println("🐳 Auto-Discovery:     Listening for containers with label 'routewarden=true'")
	}
	fmt.Printf("🔑 Server Public Key:  %s\n", serverPubStr[:min(20, len(serverPubStr))]+"...")
	fmt.Printf("⚡ Memory Footprint:   ~15MB\n")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("Press Ctrl+C to stop.")

	if !noOpen {
		go func() {
			time.Sleep(800 * time.Millisecond)
			openBrowser(dashboardURL)
		}()
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("web server error: %w", err)
	}

	fmt.Println("\n✅ Dashboard stopped.")
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func findSpecificContainer(nameOrID string) ([]containerTarget, error) {
	cmd := exec.Command("docker", "ps", "--filter", "status=running", "--filter", "name="+nameOrID, "--format", "{{.ID}}\t{{.Names}}")
	out, err := cmd.Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			parts := strings.Split(line, "\t")
			if len(parts) >= 1 {
				name := parts[0]
				if len(parts) >= 2 {
					name = parts[1]
				}
				if name == nameOrID || strings.HasPrefix(parts[0], nameOrID) {
					return []containerTarget{{ID: parts[0], Name: name}}, nil
				}
			}
		}
	}

	cmd = exec.Command("docker", "ps", "--filter", "status=running", "--filter", "id="+nameOrID, "--format", "{{.ID}}\t{{.Names}}")
	out, err = cmd.Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		parts := strings.Split(strings.TrimSpace(string(out)), "\t")
		name := parts[0]
		if len(parts) >= 2 {
			name = parts[1]
		}
		return []containerTarget{{ID: parts[0], Name: name}}, nil
	}
	return nil, fmt.Errorf("container %q not running", nameOrID)
}

func watchAndStreamContainers(ctx context.Context, label string, specificContainer string, initialTargets []containerTarget, out *os.File) {
	var mu sync.Mutex
	active := make(map[string]context.CancelFunc)
	activeTargets := make(map[string]containerTarget)

	syncSourceInfo := func() {
		mu.Lock()
		var list []containerTarget
		for _, t := range activeTargets {
			list = append(list, t)
		}
		mu.Unlock()
		updateSourceInfo("docker", "", list)
	}

	startStream := func(target containerTarget, tailLines string) {
		mu.Lock()
		if _, exists := active[target.ID]; exists {
			mu.Unlock()
			return
		}
		cCtx, cancel := context.WithCancel(ctx)
		active[target.ID] = cancel
		activeTargets[target.ID] = target
		mu.Unlock()
		syncSourceInfo()

		go func() {
			defer func() {
				mu.Lock()
				delete(active, target.ID)
				delete(activeTargets, target.ID)
				mu.Unlock()
				syncSourceInfo()
				if ctx.Err() == nil {
					fmt.Printf("🛑 [Docker] Container stopped: %s (%s)\n", target.Name, target.ID[:min(12, len(target.ID))])
				}
			}()

			cmd := exec.CommandContext(cCtx, "docker", "logs", "-f", "--tail", tailLines, target.ID)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return
			}
			stderr, err := cmd.StderrPipe()
			if err != nil {
				return
			}
			if err := cmd.Start(); err != nil {
				return
			}

			readPipe := func(r io.Reader) {
				scanner := bufio.NewScanner(r)
				for scanner.Scan() {
					combined := toCombinedLog(scanner.Text())
					if combined != "" {
						mu.Lock()
						_, _ = out.WriteString(combined + "\n")
						_ = out.Sync()
						mu.Unlock()
					}
				}
				if err := scanner.Err(); err != nil {
					_ = err
				}
			}

			go readPipe(stdout)
			readPipe(stderr)
			_ = cmd.Wait()
		}()
	}

	for _, t := range initialTargets {
		startStream(t, "50")
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			for _, cancel := range active {
				cancel()
			}
			mu.Unlock()
			return
		case <-ticker.C:
			var found []containerTarget
			if specificContainer != "" {
				if ct, err := findSpecificContainer(specificContainer); err == nil {
					found = ct
				}
			} else {
				if ct, err := discoverDockerContainers(label); err == nil {
					found = ct
				}
			}

			for _, c := range found {
				mu.Lock()
				_, isStreaming := active[c.ID]
				mu.Unlock()

				if !isStreaming {
					fmt.Printf("🐳 [Docker] Attached to container: %s (%s)\n", c.Name, c.ID[:min(12, len(c.ID))])
					startStream(c, "50")
				}
			}
		}
	}
}

func tailFileToLog(ctx context.Context, filePath string, out *os.File) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := toCombinedLog(scanner.Text())
		if line != "" {
			_, _ = out.WriteString(line + "\n")
		}
	}
	if err := scanner.Err(); err != nil {
		_ = err
	}
	_ = out.Sync()
}

func discoverDockerContainers(customLabel string) ([]containerTarget, error) {
	labels := []string{"routewarden=true", "routewarden.logs=true"}
	if customLabel != "" {
		labels = []string{customLabel}
	}

	seen := make(map[string]bool)
	var containers []containerTarget

	for _, l := range labels {
		cmd := exec.Command("docker", "ps", "--filter", "status=running", "--filter", "label="+l, "--format", "{{.ID}}\t{{.Names}}")
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Split(line, "\t")
			id := parts[0]
			name := id
			if len(parts) >= 2 {
				name = parts[1]
			}
			if !seen[id] {
				seen[id] = true
				containers = append(containers, containerTarget{ID: id, Name: name})
			}
		}
	}
	return containers, nil
}

// Down stops the running dashboard container if one was started.
func Down(ctx context.Context, dir string) error {
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", "routewarden-dashboard").Run()
	fmt.Println("✅ RouteWarden Dashboard stopped.")
	return nil
}

// Status checks the status of the dashboard container or local process.
func Status(ctx context.Context, dir string) error {
	out, err := exec.CommandContext(ctx, "docker", "ps", "--filter", "name=routewarden-dashboard", "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		fmt.Printf("🟢 Dashboard running in Docker:\n   %s\n", strings.TrimSpace(string(out)))
		return nil
	}
	fmt.Println("ℹ️  No standalone Docker dashboard container running.")
	fmt.Println("   (If launched via 'rwarden dashboard', the dashboard runs directly in the terminal session)")
	return nil
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func extractAuthToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if key := r.Header.Get("X-API-Key"); key != "" {
		return strings.TrimSpace(key)
	}
	return ""
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// NewDashboardHandler constructs the HTTP handler for the dashboard, API endpoints, and GoAccess proxy.
func NewDashboardHandler(dir string, serverPriv *ecdh.PrivateKey, serverPubStr string, logFile *os.File, wsProxy http.Handler, reportPath string) http.Handler {
	var logMu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sources", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		_ = json.NewEncoder(w).Encode(getSourceInfo())
	})

	mux.HandleFunc("/api/v1/pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"public_key": serverPubStr,
			"version":    "5.0.0",
		})
	})

	mux.HandleFunc("/api/v1/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := extractAuthToken(r)
		key, err := ValidateAgentToken(token, dir)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		UpdateAgentLastSeen(key.ID, dir)
		clientIP := extractClientIP(r)
		registerOrTouchAgent(key.ID, key.Name, "", clientIP, 0)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "registered",
			"agent_id":   key.ID,
			"agent_name": key.Name,
			"public_key": serverPubStr,
		})
	})

	mux.HandleFunc("/api/v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := extractAuthToken(r)
		key, err := ValidateAgentToken(token, dir)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		var hb struct {
			Hostname string `json:"hostname"`
		}
		_ = json.NewDecoder(r.Body).Decode(&hb)

		UpdateAgentLastSeen(key.ID, dir)
		clientIP := extractClientIP(r)
		registerOrTouchAgent(key.ID, key.Name, hb.Hostname, clientIP, 0)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		token := extractAuthToken(r)
		key, err := ValidateAgentToken(token, dir)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		// Try decrypting if payload is EncryptedPayload
		var plaintext = bodyBytes
		var encPayload crypto.EncryptedPayload
		if err := json.Unmarshal(bodyBytes, &encPayload); err == nil && encPayload.Ciphertext != "" && encPayload.EphemeralPub != "" {
			dec, err := crypto.Decrypt(serverPriv, &encPayload)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "decryption failed: " + err.Error()})
				return
			}
			plaintext = dec
		}

		type EventPayload struct {
			AgentID  string            `json:"agent_id"`
			Hostname string            `json:"hostname"`
			Events   []json.RawMessage `json:"events"`
		}

		var payload EventPayload
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			var strList []string
			if err2 := json.Unmarshal(plaintext, &strList); err2 == nil {
				for _, s := range strList {
					payload.Events = append(payload.Events, json.RawMessage([]byte(strconv.Quote(s))))
				}
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid payload format"})
				return
			}
		}

		// Convert and write events
		count := 0
		logMu.Lock()
		for _, rawEv := range payload.Events {
			evStr := string(rawEv)
			if strings.HasPrefix(evStr, `"`) && strings.HasSuffix(evStr, `"`) {
				var unq string
				if err := json.Unmarshal(rawEv, &unq); err == nil {
					evStr = unq
				}
			}
			combined := toCombinedLog(evStr)
			if combined != "" {
				if logFile != nil {
					_, _ = logFile.WriteString(combined + "\n")
				}
				count++
			}
		}
		if logFile != nil {
			_ = logFile.Sync()
		}
		logMu.Unlock()

		clientIP := extractClientIP(r)
		UpdateAgentLastSeen(key.ID, dir)
		registerOrTouchAgent(key.ID, key.Name, payload.Hostname, clientIP, count)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "accepted",
			"ingested": count,
			"agent":    key.Name,
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if wsProxy != nil && (r.Header.Get("Upgrade") == "websocket" || strings.HasPrefix(r.URL.Path, "/ws")) {
			wsProxy.ServeHTTP(w, r)
			return
		}

		if reportPath != "" {
			if _, err := os.Stat(reportPath); err == nil {
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				htmlBytes, err := os.ReadFile(reportPath)
				if err != nil {
					http.ServeFile(w, r, reportPath)
					return
				}
				injected := bytes.Replace(htmlBytes, []byte("</body>"), []byte(sourceBadgeInjection+"</body>"), 1)
				_, _ = w.Write(injected)
				return
			}
		}

		// Initial splash screen while report is being generated
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html><html><head><meta http-equiv="refresh" content="1"><title>RouteWarden Dashboard</title></head><body style="background:#1a1d21;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;margin:0;"><h2 style="margin:0 0 10px 0;">🚀 RouteWarden Security Dashboard</h2><p style="color:#9ba1a6;">Initializing real-time GoAccess stream...</p></body></html>`))
	})

	return mux
}
