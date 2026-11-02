package engine

import (
	"testing"
)

func TestDetectBrowserImpersonation(t *testing.T) {
	tests := []struct {
		name       string
		ua         string
		headers    map[string]string
		wantBlock  bool
		wantReason string
	}{
		{
			name: "Valid Chrome Browser with all companion headers",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			headers: map[string]string{
				"Accept-Language":    "en-US,en;q=0.9",
				"Accept-Encoding":    "gzip, deflate, br",
				"Sec-CH-UA":          `"Chromium";v="120", "Google Chrome";v="120", "Not?A_Brand";v="24"`,
				"Sec-CH-UA-Mobile":   "?0",
				"Sec-CH-UA-Platform": `"macOS"`,
				"Sec-Fetch-Site":     "none",
				"Sec-Fetch-Mode":     "navigate",
				"Sec-Fetch-Dest":     "document",
			},
			wantBlock: false,
		},
		{
			name: "Mobile mismatch: Desktop Mac UA with Sec-CH-UA-Mobile: ?1",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			headers: map[string]string{
				"Accept-Language":    "en-US,en;q=0.9",
				"Accept-Encoding":    "gzip, deflate, br",
				"Sec-CH-UA":          `"Chromium";v="120", "Google Chrome";v="120", "Not?A_Brand";v="24"`,
				"Sec-CH-UA-Mobile":   "?1",
				"Sec-CH-UA-Platform": `"macOS"`,
				"Sec-Fetch-Site":     "none",
				"Sec-Fetch-Mode":     "navigate",
				"Sec-Fetch-Dest":     "document",
			},
			wantBlock:  true,
			wantReason: "sec_ch_ua_mobile_mismatch",
		},
		{
			name: "Brand mismatch: Firefox claiming Chromium in Sec-CH-UA",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
			headers: map[string]string{
				"Accept-Language": "en-US,en;q=0.9",
				"Accept-Encoding": "gzip, deflate, br",
				"Sec-CH-UA":       `"Chromium";v="120"`,
			},
			wantBlock:  true,
			wantReason: "sec_ch_ua_brand_mismatch",
		},
		{
			name: "Fetch mode mismatch: Sec-Fetch-Dest document with cors mode",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			headers: map[string]string{
				"Accept-Language":    "en-US,en;q=0.9",
				"Accept-Encoding":    "gzip, deflate, br",
				"Sec-CH-UA":          `"Chromium";v="120", "Not_A Brand";v="24"`,
				"Sec-CH-UA-Mobile":   "?0",
				"Sec-CH-UA-Platform": `"Windows"`,
				"Sec-Fetch-Site":     "same-origin",
				"Sec-Fetch-Mode":     "cors",
				"Sec-Fetch-Dest":     "document",
			},
			wantBlock:  true,
			wantReason: "sec_fetch_mode_mismatch",
		},
		{
			name: "Missing GREASE brand in modern Chromium Sec-CH-UA",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			headers: map[string]string{
				"Accept-Language":    "en-US,en;q=0.9",
				"Accept-Encoding":    "gzip, deflate, br",
				"Sec-CH-UA":          `"Chromium";v="120", "Google Chrome";v="120"`,
				"Sec-CH-UA-Mobile":   "?0",
				"Sec-CH-UA-Platform": `"Windows"`,
				"Sec-Fetch-Site":     "same-origin",
				"Sec-Fetch-Mode":     "navigate",
				"Sec-Fetch-Dest":     "document",
			},
			wantBlock:  true,
			wantReason: "missing_grease_brand",
		},
		{
			name: "Missing Accept-Language",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			headers: map[string]string{
				"Accept-Encoding": "gzip, deflate",
			},
			wantBlock:  true,
			wantReason: "missing_accept_language",
		},
		{
			name: "Missing Accept-Encoding",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			headers: map[string]string{
				"Accept-Language": "en-US,en;q=0.9",
			},
			wantBlock:  true,
			wantReason: "missing_accept_encoding",
		},
		{
			name: "Sec-CH-UA-Platform mismatch: Claimed Windows in UA, Linux in Sec-CH-UA-Platform",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			headers: map[string]string{
				"Accept-Language":    "en-US,en;q=0.9",
				"Accept-Encoding":    "gzip, deflate",
				"Sec-CH-UA-Platform": `"Linux"`,
			},
			wantBlock:  true,
			wantReason: "sec_ch_ua_platform_mismatch",
		},
		{
			name: "Missing Sec-CH-UA on modern Chrome v120 with Sec-CH-UA-Platform",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			headers: map[string]string{
				"Accept-Language":    "en-US,en;q=0.9",
				"Accept-Encoding":    "gzip, deflate",
				"Sec-CH-UA-Platform": `"Windows"`,
			},
			wantBlock:  true,
			wantReason: "missing_sec_ch_ua",
		},
		{
			name: "Missing Sec-Fetch headers on modern Chrome v120",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			headers: map[string]string{
				"Accept-Language":    "en-US,en;q=0.9",
				"Accept-Encoding":    "gzip, deflate",
				"Sec-CH-UA":          `"Chromium";v="120"`,
				"Sec-CH-UA-Platform": `"Windows"`,
			},
			wantBlock:  true,
			wantReason: "missing_sec_fetch",
		},
		{
			name: "Search engine bot exempt from browser impersonation checks",
			ua:   "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			headers: map[string]string{
				"Accept-Encoding": "gzip, deflate",
			},
			wantBlock: false,
		},
		{
			name:       "Empty User-Agent ignored",
			ua:         "",
			headers:    nil,
			wantBlock:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := DetectBrowserImpersonation(tt.ua, tt.headers)
			if blocked != tt.wantBlock {
				t.Fatalf("expected blocked=%v, got %v (reason: %s)", tt.wantBlock, blocked, reason)
			}
			if tt.wantReason != "" && reason != tt.wantReason {
				t.Errorf("expected reason=%s, got %s", tt.wantReason, reason)
			}
		})
	}
}

func TestDetectScriptClient(t *testing.T) {
	tests := []struct {
		name       string
		ua         string
		headers    map[string]string
		wantBlock  bool
		wantReason string
	}{
		{
			name: "python-requests UA",
			ua:   "python-requests/2.31.0",
			wantBlock: true,
		},
		{
			name: "axios client library UA",
			ua:   "axios/1.6.2",
			wantBlock: true,
		},
		{
			name: "curl client UA",
			ua:   "curl/8.4.0",
			wantBlock: true,
		},
		{
			name: "guzzle client UA",
			ua:   "GuzzleHttp/7",
			wantBlock: true,
		},
		{
			name: "reqwest client UA",
			ua:   "reqwest/0.11.22",
			wantBlock: true,
		},
		{
			name: "Playwright automation header",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			headers: map[string]string{
				"X-Playwright": "1",
			},
			wantBlock:  true,
			wantReason: "playwright_headless",
		},
		{
			name: "Cypress automation header",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			headers: map[string]string{
				"X-Cypress": "1",
			},
			wantBlock:  true,
			wantReason: "cypress_headless",
		},
		{
			name: "Puppeteer automation header",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			headers: map[string]string{
				"X-Puppeteer": "1",
			},
			wantBlock:  true,
			wantReason: "puppeteer_headless",
		},
		{
			name: "Sec-WebDriver automation header",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			headers: map[string]string{
				"Sec-WebDriver": "true",
			},
			wantBlock:  true,
			wantReason: "webdriver_automation",
		},
		{
			name: "Clean normal browser",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			headers: map[string]string{
				"Accept-Language": "en-US",
			},
			wantBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := DetectScriptClient(tt.ua, tt.headers)
			if blocked != tt.wantBlock {
				t.Fatalf("expected blocked=%v, got %v (reason: %s)", tt.wantBlock, blocked, reason)
			}
			if tt.wantReason != "" && reason != tt.wantReason {
				t.Errorf("expected reason=%s, got %s", tt.wantReason, reason)
			}
		})
	}
}

func TestDetectBrowserHeaderOrder(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	// 1. Valid Chrome order (Sec-CH-UA before User-Agent and Accept)
	validOrder := []string{"Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "User-Agent", "Accept"}
	blocked, reason := DetectBrowserHeaderOrder(validOrder, ua)
	if blocked {
		t.Fatalf("expected valid header order to pass, got blocked=%v, reason=%s", blocked, reason)
	}

	// 2. Anomaly: User-Agent before Sec-CH-UA
	spoofedUAFirst := []string{"Host", "User-Agent", "Accept", "sec-ch-ua", "sec-ch-ua-mobile"}
	blocked, reason = DetectBrowserHeaderOrder(spoofedUAFirst, ua)
	if !blocked || reason != "header_order_anomaly" {
		t.Fatalf("expected header_order_anomaly when User-Agent appears before Sec-CH-UA, got blocked=%v, reason=%s", blocked, reason)
	}

	// 3. Anomaly: Accept before Sec-CH-UA
	spoofedAcceptFirst := []string{"Host", "Accept", "User-Agent", "sec-ch-ua"}
	blocked, reason = DetectBrowserHeaderOrder(spoofedAcceptFirst, ua)
	if !blocked || reason != "header_order_anomaly" {
		t.Fatalf("expected header_order_anomaly when Accept appears before Sec-CH-UA, got blocked=%v, reason=%s", blocked, reason)
	}
}
