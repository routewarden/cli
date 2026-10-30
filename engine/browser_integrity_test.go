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
				"Accept-Language":     "en-US,en;q=0.9",
				"Accept-Encoding":     "gzip, deflate, br",
				"Sec-CH-UA-Platform":  `"macOS"`,
				"Sec-Fetch-Site":      "none",
				"Sec-Fetch-Mode":      "navigate",
				"Sec-Fetch-Dest":      "document",
			},
			wantBlock: false,
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
			name: "Missing Sec-Fetch headers on modern Chrome v120",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			headers: map[string]string{
				"Accept-Language":    "en-US,en;q=0.9",
				"Accept-Encoding":    "gzip, deflate",
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
			name: "Playwright automation header",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			headers: map[string]string{
				"X-Playwright": "1",
			},
			wantBlock:  true,
			wantReason: "playwright_headless",
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
