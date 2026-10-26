package config

import "testing"

func TestASNConfigValidation(t *testing.T) {
	for _, allowed := range [][]string{{"0"}, {"-1"}, {"+1"}, {"AS"}, {"4294967296"}} {
		if err := validateASNConfig(allowed, "asn.json"); err == nil {
			t.Errorf("accepted %v", allowed)
		}
	}
	if err := validateASNConfig([]string{"AS64500"}, ""); err == nil {
		t.Error("accepted missing DB path")
	}
	if err := validateASNConfig([]string{"AS64500", "4294967295"}, "asn.json"); err != nil {
		t.Fatal(err)
	}
	if err := validateASNConfig(nil, ""); err != nil {
		t.Fatal(err)
	}
}
