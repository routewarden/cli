package main

import (
	"strings"
	"testing"
)

func TestGenerateManPage_Unit(t *testing.T) {
	man := GenerateManPage(version)

	expectedHeader := `.TH RWARDEN 1 "October 2026" "rwarden ` + version + `" "RouteWarden Manual"`
	if !strings.Contains(man, expectedHeader) {
		t.Errorf("missing roff header in man page: %s", man[:min(100, len(man))])
	}

	requiredSections := []string{
		".SH NAME",
		".SH SYNOPSIS",
		".SH DESCRIPTION",
		".SH COMMANDS",
		`\fBtest\fR`,
		`\fBvalidate\fR`,
		`\fBgenerate\fR`,
		`\fBaudit\fR`,
		`\fBdiff\fR`,
		`\fBmonitor\fR`,
		`\fBtui\fR`,
		`\fBcompletion\fR`,
		`\fBman\fR`,
		`\fBsandbox\fR`,
		`\fBdashboard\fR`,
		`\fBup\fR`,
		`\fBkeys\fR`,
		`\fBregister\fR`,
		`\fBpush\fR`,
		`\fBtcp\fR`,
		`\fBstatus\fR`,
		`\fBstop\fR`,
		`\fBcleanup\fR`,
		`\fBschema\fR`,
		`\fBversion\fR`,
		".SH EXAMPLES",
		".SH AUTHOR",
	}

	for _, sec := range requiredSections {
		if !strings.Contains(man, sec) {
			t.Errorf("man page missing expected section or directive: %s", sec)
		}
	}

	if strings.Contains(strings.ToLower(man), "goaccess") {
		t.Errorf("man page must not contain goaccess reference")
	}

	if !strings.Contains(man, "real-time SOC security dashboard") {
		t.Errorf("man page must reference real-time SOC security dashboard")
	}
}
