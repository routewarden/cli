package engine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultPoWDifficulty represents the standard number of leading zero bits required (16 bits ~= 65,536 iterations, ~25ms in JS).
	DefaultPoWDifficulty = 16
	// DefaultPoWTimeoutSeconds is the challenge lifetime in seconds (5 minutes).
	DefaultPoWTimeoutSeconds = 300
	// DefaultPoWSecret is the fallback secret used to sign PoW challenges if none is provided.
	DefaultPoWSecret = "routewarden-pow-challenge-seed-secret"
)

// leadingZeros8 returns the count of leading zero bits in a byte (0..8).
func leadingZeros8(b byte) int {
	if b >= 128 {
		return 0
	}
	if b >= 64 {
		return 1
	}
	if b >= 32 {
		return 2
	}
	if b >= 16 {
		return 3
	}
	if b >= 8 {
		return 4
	}
	if b >= 4 {
		return 5
	}
	if b >= 2 {
		return 6
	}
	if b >= 1 {
		return 7
	}
	return 8
}

// CountLeadingZeroBits returns the total number of consecutive leading zero bits in a slice.
func CountLeadingZeroBits(data []byte) int {
	zeros := 0
	for _, b := range data {
		if b == 0 {
			zeros += 8
		} else {
			zeros += leadingZeros8(b)
			break
		}
	}
	return zeros
}

// NormalizePoWIP strips port and zone identifier from IP string for consistent binding.
func NormalizePoWIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	ip = strings.Trim(ip, "[]")
	if idx := strings.IndexByte(ip, '%'); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// GeneratePoWChallenge creates a signed challenge token for clientIP.
// Token format: <timestamp>.<difficulty>.<salt>.<signature>
func GeneratePoWChallenge(clientIP, secret string, difficulty int, now time.Time) (string, error) {
	if difficulty <= 0 {
		difficulty = DefaultPoWDifficulty
	}
	if secret == "" {
		secret = DefaultPoWSecret
	}
	normIP := NormalizePoWIP(clientIP)

	saltBytes := make([]byte, 8)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", fmt.Errorf("failed to generate random salt: %w", err)
	}
	salt := hex.EncodeToString(saltBytes)

	timestamp := strconv.FormatInt(now.Unix(), 10)
	diffStr := strconv.Itoa(difficulty)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(normIP + ":" + timestamp + ":" + diffStr + ":" + salt))
	sig := hex.EncodeToString(mac.Sum(nil))

	return timestamp + "." + diffStr + "." + salt + "." + sig, nil
}

// VerifyPoWSolution verifies a solved challenge submitted by clientIP.
// Solution format: <timestamp>.<difficulty>.<salt>.<signature>.<nonce>
func VerifyPoWSolution(clientIP, secret, solution string, timeoutSeconds int, now time.Time) (bool, string) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = DefaultPoWTimeoutSeconds
	}
	if secret == "" {
		secret = DefaultPoWSecret
	}
	normIP := NormalizePoWIP(clientIP)

	parts := strings.Split(strings.TrimSpace(solution), ".")
	if len(parts) != 5 {
		return false, "invalid_pow_format"
	}

	tsStr, diffStr, salt, sig, nonceStr := parts[0], parts[1], parts[2], parts[3], parts[4]

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false, "invalid_pow_timestamp"
	}

	diff, err := strconv.Atoi(diffStr)
	if err != nil || diff <= 0 || diff > 64 {
		return false, "invalid_pow_difficulty"
	}

	if _, err := strconv.ParseUint(nonceStr, 10, 64); err != nil {
		return false, "invalid_pow_nonce"
	}

	// 1. Time expiration check
	elapsed := now.Unix() - ts
	if elapsed < -10 || elapsed > int64(timeoutSeconds) {
		return false, "expired_pow"
	}

	// 2. HMAC signature verification
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(normIP + ":" + tsStr + ":" + diffStr + ":" + salt))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return false, "invalid_pow_signature"
	}

	// 3. Hashcash computation check: SHA-256(challenge + ":" + nonce) has >= difficulty leading zero bits
	challenge := tsStr + "." + diffStr + "." + salt + "." + sig
	payload := challenge + ":" + nonceStr
	h := sha256.Sum256([]byte(payload))
	zeros := CountLeadingZeroBits(h[:])

	if zeros < diff {
		return false, "insufficient_pow_work"
	}

	return true, ""
}

// SolvePoW finds the nonce that satisfies challenge for test and verification purposes.
func SolvePoW(challenge string, difficulty int) uint64 {
	var nonce uint64
	for {
		payload := challenge + ":" + strconv.FormatUint(nonce, 10)
		h := sha256.Sum256([]byte(payload))
		if CountLeadingZeroBits(h[:]) >= difficulty {
			return nonce
		}
		nonce++
	}
}

// GeneratePoWHTML returns the self-contained, responsive challenge page with inline Web Worker solver.
func GeneratePoWHTML(challenge string, difficulty, timeoutSeconds int) string {
	if timeoutSeconds <= 0 {
		timeoutSeconds = DefaultPoWTimeoutSeconds
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Verification &middot; RouteWarden</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(17, 24, 39, 0.85);
      --border: rgba(55, 65, 81, 0.6);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #3b82f6;
      --accent-glow: rgba(59, 130, 246, 0.35);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .card {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 2.5rem;
      max-width: 440px;
      width: 100%%;
      text-align: center;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
    }
    .spinner-box {
      position: relative;
      width: 64px;
      height: 64px;
      margin: 0 auto 1.5rem;
    }
    .spinner {
      width: 64px;
      height: 64px;
      border: 3px solid rgba(59, 130, 246, 0.15);
      border-top-color: var(--accent);
      border-radius: 50%%;
      animation: spin 1s linear infinite;
      box-shadow: 0 0 20px var(--accent-glow);
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    h1 { font-size: 1.35rem; font-weight: 600; margin-bottom: 0.75rem; letter-spacing: -0.01em; }
    p { font-size: 0.925rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 1.5rem; }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 14px;
      border-radius: 9999px;
      background: rgba(59, 130, 246, 0.1);
      border: 1px solid rgba(59, 130, 246, 0.25);
      font-size: 0.775rem;
      color: #93c5fd;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .dot { width: 6px; height: 6px; border-radius: 50%%; background: var(--accent); animation: pulse 1.5s ease-in-out infinite; }
    @keyframes pulse { 0%%, 100%% { opacity: 0.4; } 50%% { opacity: 1; } }
    noscript { color: #f87171; font-size: 0.875rem; margin-top: 1rem; display: block; }
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner-box">
      <div class="spinner"></div>
    </div>
    <h1>Verifying Your Connection</h1>
    <p>Please wait momentarily while your browser verifies security authorization with cryptographic proof-of-work.</p>
    <div class="badge">
      <span class="dot"></span>
      <span id="status">Solving proof-of-work challenge&hellip;</span>
    </div>
    <noscript>
      <p>JavaScript is required to complete this security verification. Please enable JavaScript in your browser to proceed.</p>
    </noscript>
  </div>

  <script>
    (function() {
      const challenge = "%s";
      const difficulty = %d;
      const timeout = %d;
      const targetBytes = Math.floor(difficulty / 8);
      const remBits = difficulty %% 8;
      const remMask = (0xFF << (8 - remBits)) & 0xFF;

      function checkLeadingZeros(bytes) {
        for (let i = 0; i < targetBytes; i++) {
          if (bytes[i] !== 0) return false;
        }
        if (remBits > 0) {
          if ((bytes[targetBytes] & remMask) !== 0) return false;
        }
        return true;
      }

      async function solve() {
        const enc = new TextEncoder();
        let nonce = 0;
        const batchSize = 500;
        
        while (true) {
          const promises = [];
          for (let i = 0; i < batchSize; i++) {
            const currentNonce = nonce + i;
            const data = enc.encode(challenge + ":" + currentNonce);
            promises.push(crypto.subtle.digest("SHA-256", data).then(buf => ({
              nonce: currentNonce,
              bytes: new Uint8Array(buf)
            })));
          }

          const results = await Promise.all(promises);
          for (let i = 0; i < results.length; i++) {
            if (checkLeadingZeros(results[i].bytes)) {
              const solution = challenge + "." + results[i].nonce;
              document.cookie = "__rw_pow=" + encodeURIComponent(solution) + "; path=/; max-age=" + timeout + "; SameSite=Lax";
              document.getElementById("status").textContent = "Verified! Redirecting\u2026";
              window.location.reload();
              return;
            }
          }
          nonce += batchSize;
        }
      }

      if (window.crypto && window.crypto.subtle) {
        solve().catch(function(err) {
          console.error("PoW error", err);
        });
      } else {
        document.getElementById("status").textContent = "Crypto API unavailable";
      }
    })();
  </script>
</body>
</html>`, challenge, difficulty, timeoutSeconds)
}

