package engine

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	reBrowserLike = regexp.MustCompile(`(?i)(Mozilla/\d+\.\d+|AppleWebKit/\d+|Gecko/\d+|Chrome/\d+|Safari/\d+|Firefox/\d+|Edg/\d+)`)
	reChromeVer   = regexp.MustCompile(`(?:Chrome|Chromium|Edg)/(\d+)`)

	reScriptClientUA = regexp.MustCompile(`(?i)(` +
		`python-requests|requests/|aiohttp|httpx|scrapy|urllib/|urllib3|tornado|` +
		`axios|node-fetch|undici|got/\d+|superagent|needle/\d+|` +
		`go-http-client|` +
		`okhttp|apache-httpclient|java/\d+|httpclient|` +
		`faraday|httparty|rest-client|` +
		`curl/\d+|wget/\d+|libwww-perl|phantomjs|headlesschrome|puppeteer|playwright` +
		`)`)
)

func getHeaderCaseInsensitive(headers map[string]string, key string) string {
	if headers == nil {
		return ""
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// DetectBrowserImpersonation inspects whether a request claiming to be an interactive
// desktop or mobile browser lacks required companion headers or presents contradictory Client Hints.
func DetectBrowserImpersonation(ua string, headers map[string]string) (bool, string) {
	uaTrim := strings.TrimSpace(ua)
	if uaTrim == "" {
		return false, ""
	}

	// Only evaluate requests that claim to be a standard browser
	if !reBrowserLike.MatchString(uaTrim) {
		return false, ""
	}

	// Exclude search engine bots that have their own FCrDNS validation (Googlebot, Bingbot, Applebot)
	if claimsBot, _ := DetectSearchEngineBot(uaTrim); claimsBot {
		return false, ""
	}

	// 1. Mandatory companion headers expected from any real interactive browser
	acceptLang := getHeaderCaseInsensitive(headers, "Accept-Language")
	if strings.TrimSpace(acceptLang) == "" {
		return true, "missing_accept_language"
	}

	acceptEnc := getHeaderCaseInsensitive(headers, "Accept-Encoding")
	if strings.TrimSpace(acceptEnc) == "" {
		return true, "missing_accept_encoding"
	}

	// 2. Client Hints platform cross-check (Sec-CH-UA-Platform vs User-Agent OS)
	secPlatformRaw := getHeaderCaseInsensitive(headers, "Sec-CH-UA-Platform")
	if secPlatformRaw != "" {
		platform := strings.ToLower(strings.Trim(strings.TrimSpace(secPlatformRaw), "\""))
		uaLower := strings.ToLower(uaTrim)

		claimedWindows := strings.Contains(uaLower, "windows")
		claimedMac := strings.Contains(uaLower, "macintosh") || strings.Contains(uaLower, "mac os x")
		claimedLinux := strings.Contains(uaLower, "linux") && !strings.Contains(uaLower, "android")
		claimedAndroid := strings.Contains(uaLower, "android")
		claimedIOS := strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "ipad") || strings.Contains(uaLower, "ipod")

		switch platform {
		case "windows":
			if !claimedWindows {
				return true, "sec_ch_ua_platform_mismatch"
			}
		case "macos", "mac os x":
			if !claimedMac {
				return true, "sec_ch_ua_platform_mismatch"
			}
		case "linux":
			if !claimedLinux {
				return true, "sec_ch_ua_platform_mismatch"
			}
		case "android":
			if !claimedAndroid {
				return true, "sec_ch_ua_platform_mismatch"
			}
		case "ios":
			if !claimedIOS {
				return true, "sec_ch_ua_platform_mismatch"
			}
		}
	}

	// 3. Modern Chromium Fetch Metadata validation (Sec-Fetch-* headers)
	if match := reChromeVer.FindStringSubmatch(uaTrim); len(match) > 1 {
		ver, err := strconv.Atoi(match[1])
		if err == nil && ver >= 90 {
			fetchSite := getHeaderCaseInsensitive(headers, "Sec-Fetch-Site")
			fetchMode := getHeaderCaseInsensitive(headers, "Sec-Fetch-Mode")
			fetchDest := getHeaderCaseInsensitive(headers, "Sec-Fetch-Dest")
			if fetchSite == "" && fetchMode == "" && fetchDest == "" {
				return true, "missing_sec_fetch"
			}
		}
	}

	return false, ""
}

// DetectScriptClient inspects whether a request originates from an automated HTTP client library
// or headless automation framework.
func DetectScriptClient(ua string, headers map[string]string) (bool, string) {
	// 1. Headless / automation framework header indicators
	if getHeaderCaseInsensitive(headers, "X-Playwright") != "" {
		return true, "playwright_headless"
	}
	if getHeaderCaseInsensitive(headers, "X-Puppeteer") != "" {
		return true, "puppeteer_headless"
	}
	if getHeaderCaseInsensitive(headers, "X-Selenium") != "" {
		return true, "selenium_headless"
	}
	if getHeaderCaseInsensitive(headers, "X-Scrapy") != "" {
		return true, "scrapy_crawler"
	}
	if getHeaderCaseInsensitive(headers, "Sec-WebDriver") != "" || getHeaderCaseInsensitive(headers, "X-Headless") != "" {
		return true, "webdriver_automation"
	}

	// 2. Library User-Agent regex inspection
	uaTrim := strings.TrimSpace(ua)
	if uaTrim != "" {
		if loc := reScriptClientUA.FindString(uaTrim); loc != "" {
			return true, strings.ToLower(loc)
		}
	}

	return false, ""
}

