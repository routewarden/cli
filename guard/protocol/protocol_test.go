package protocol

import (
	"bufio"
	"strings"
	"testing"
)

func TestExtractDomainAndEmail(t *testing.T) {
	cases := []struct {
		input  string
		email  string
		domain string
	}{
		{"<attacker@spammer.ru>", "attacker@spammer.ru", "spammer.ru"},
		{"user@example.com", "user@example.com", "example.com"},
		{"<root@sub.domain.co.uk>", "root@sub.domain.co.uk", "sub.domain.co.uk"},
		{"   <test@evil.xyz>  ", "test@evil.xyz", "evil.xyz"},
	}

	for _, c := range cases {
		em := extractEmailAddress(c.input)
		if em != c.email {
			t.Errorf("extractEmailAddress(%q): got %q, want %q", c.input, em, c.email)
		}
		dom := extractDomain(em)
		if dom != c.domain {
			t.Errorf("extractDomain(%q): got %q, want %q", em, dom, c.domain)
		}
	}
}

func TestSMTPDomainBlocked(t *testing.T) {
	proxy := &SMTPProxy{
		opts: SMTPInspectorOptions{
			BlockedSenderDomains: []string{"spammer.ru", "*.evil.com", "*.biz"},
		},
	}

	cases := []struct {
		domain  string
		blocked bool
	}{
		{"spammer.ru", true},
		{"sub.spammer.ru", false}, // exact match pattern
		{"bot.evil.com", true},    // wildcard pattern
		{"deep.nested.evil.com", true},
		{"good.com", false},
		{"mycompany.biz", true},
		{"corp.org", false},
	}

	for _, c := range cases {
		got := proxy.isDomainBlocked(c.domain)
		if got != c.blocked {
			t.Errorf("isDomainBlocked(%q): got %v, want %v", c.domain, got, c.blocked)
		}
	}
}

func TestReadSMTPResponse(t *testing.T) {
	raw := "250-mail.example.com Hello\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250 OK\r\n"
	r := bufio.NewReader(strings.NewReader(raw))

	resp, err := readSMTPResponse(r)
	if err != nil {
		t.Fatalf("readSMTPResponse failed: %v", err)
	}
	if resp != raw {
		t.Errorf("readSMTPResponse: got %q, want %q", resp, raw)
	}
	if responseCode(resp) != 250 {
		t.Errorf("responseCode: got %d, want 250", responseCode(resp))
	}
}

func TestPOP3MultiLineDetection(t *testing.T) {
	if !isPOP3MultiLineCmd("CAPA") {
		t.Error("expected CAPA to be multi-line")
	}
	if !isPOP3MultiLineCmd("LIST") {
		t.Error("expected LIST to be multi-line")
	}
	if !isPOP3MultiLineCmd("UIDL") {
		t.Error("expected UIDL to be multi-line")
	}
	if isPOP3MultiLineCmd("USER") {
		t.Error("expected USER to not be multi-line")
	}
	if isPOP3MultiLineCmd("PASS") {
		t.Error("expected PASS to not be multi-line")
	}
}

func TestReadPOP3MultiLineResponse(t *testing.T) {
	raw := "+OK Capability list follows\r\nUSER\r\nRESP-CODES\r\nSTLS\r\n.\r\n"
	r := bufio.NewReader(strings.NewReader(raw))

	resp, err := readPOP3MultiLineResponse(r)
	if err != nil {
		t.Fatalf("readPOP3MultiLineResponse failed: %v", err)
	}
	if resp != raw {
		t.Errorf("got %q, want %q", resp, raw)
	}
}
