package engine

import (
	"testing"
)

func TestDiffConfigs_Identical(t *testing.T) {
	base := CreateConfig()
	candidate := CreateConfig()

	diff := DiffConfigs(base, candidate, "base.json", "candidate.json")
	if diff.HasDifferences {
		t.Error("expected no differences between identical configs")
	}
	if diff.Impact != DiffImpactNeutral {
		t.Errorf("expected neutral impact, got %s", diff.Impact)
	}
}

func TestDiffConfigs_RelaxedPosture(t *testing.T) {
	base := CreateConfig()
	base.BlockPatterns = []string{`(?i)\.env`, `(?i)\.git`}

	candidate := CreateConfig()
	candidate.BlockPatterns = []string{`(?i)\.env`} // removed .git
	candidate.AllowPatterns = []string{"/api/.*"}   // added broad allow

	diff := DiffConfigs(base, candidate, "base.json", "candidate.json")
	if !diff.HasDifferences {
		t.Error("expected differences to be detected")
	}
	if diff.Impact != DiffImpactRelaxed {
		t.Errorf("expected RELAXED impact, got %s", diff.Impact)
	}
	if len(diff.BlockPatterns.Removed) != 1 || diff.BlockPatterns.Removed[0] != `(?i)\.git` {
		t.Errorf("expected .git to be in removed block patterns, got %+v", diff.BlockPatterns.Removed)
	}
	if len(diff.AllowPatterns.Added) != 1 {
		t.Errorf("expected 1 added allow pattern, got %+v", diff.AllowPatterns.Added)
	}
}

func TestDiffConfigs_HardenedPosture(t *testing.T) {
	base := CreateConfig()
	base.BlockPatterns = []string{`(?i)\.env`}

	candidate := CreateConfig()
	candidate.BlockPatterns = []string{`(?i)\.env`, `(?i)\.git`, `(?i)\.bak`}
	candidate.CheckQuery = true

	diff := DiffConfigs(base, candidate, "base.json", "candidate.json")
	if !diff.HasDifferences {
		t.Error("expected differences to be detected")
	}
	if diff.Impact != DiffImpactHardened {
		t.Errorf("expected HARDENED impact, got %s", diff.Impact)
	}
	if len(diff.BlockPatterns.Added) != 2 {
		t.Errorf("expected 2 added block patterns, got %d", len(diff.BlockPatterns.Added))
	}
	if _, exists := diff.Properties["checkQuery"]; !exists {
		t.Error("expected checkQuery scalar property diff")
	}
}

func TestDiffConfigs_BodyPatternsAndResponse(t *testing.T) {
	base := CreateConfig()
	base.CheckBody = true
	base.CheckBodyPatterns = []string{`(?i)drop\s+table`, `(?i)union\s+select`}
	base.Response = &ResponseConfig{
		Mode:       "text",
		StatusCode: 403,
	}

	candidate := CreateConfig()
	candidate.CheckBody = false                                // relaxed
	candidate.CheckBodyPatterns = []string{`(?i)drop\s+table`} // removed union select
	candidate.CheckBodyMaxBytes = 131072
	candidate.CustomResponseText = "Custom WAF Block"
	candidate.Response = &ResponseConfig{
		Mode:       "json",
		StatusCode: 400,
	}

	diff := DiffConfigs(base, candidate, "base.json", "candidate.json")
	if !diff.HasDifferences {
		t.Fatal("expected differences")
	}
	if diff.Impact != DiffImpactRelaxed {
		t.Errorf("expected RELAXED impact due to disabled checkBody and removed pattern, got %s", diff.Impact)
	}
	if len(diff.CheckBodyPatterns.Removed) != 1 || diff.CheckBodyPatterns.Removed[0] != `(?i)union\s+select` {
		t.Errorf("expected removed union select pattern, got %+v", diff.CheckBodyPatterns.Removed)
	}
	if _, ok := diff.Properties["checkBody"]; !ok {
		t.Error("expected checkBody property diff")
	}
	if _, ok := diff.Properties["checkBodyMaxBytes"]; !ok {
		t.Error("expected checkBodyMaxBytes property diff")
	}
	if _, ok := diff.Properties["customResponseText"]; !ok {
		t.Error("expected customResponseText property diff")
	}
	if prop, ok := diff.Properties["response.mode"]; !ok || prop.New != "json" {
		t.Errorf("expected response.mode property diff to json, got %+v", prop)
	}
	if prop, ok := diff.Properties["response.statusCode"]; !ok || prop.New != 400 {
		t.Errorf("expected response.statusCode property diff to 400, got %+v", prop)
	}
}

func TestDiffConfigs_NilSafety(t *testing.T) {
	// Neither base nor candidate should panic when nil
	diff1 := DiffConfigs(nil, nil, "nil1", "nil2")
	if diff1 == nil {
		t.Fatal("expected non-nil PolicyDiff for nil inputs")
	}

	cfg := CreateConfig()
	diff2 := DiffConfigs(nil, cfg, "nil", "valid")
	if diff2 == nil {
		t.Fatal("expected non-nil PolicyDiff for nil base")
	}

	diff3 := DiffConfigs(cfg, nil, "valid", "nil")
	if diff3 == nil {
		t.Fatal("expected non-nil PolicyDiff for nil candidate")
	}
}

func TestDiffConfigs_DeduplicateSlices(t *testing.T) {
	base := CreateConfig()
	base.BlockPatterns = []string{`(?i)\.env`, `(?i)\.env`}

	candidate := CreateConfig()
	candidate.BlockPatterns = []string{`(?i)\.git`, `(?i)\.git`, `(?i)\.git`}

	diff := DiffConfigs(base, candidate, "base.json", "candidate.json")
	if len(diff.BlockPatterns.Added) != 1 || diff.BlockPatterns.Added[0] != `(?i)\.git` {
		t.Errorf("expected exactly 1 deduplicated added pattern, got %+v", diff.BlockPatterns.Added)
	}
	if len(diff.BlockPatterns.Removed) != 1 || diff.BlockPatterns.Removed[0] != `(?i)\.env` {
		t.Errorf("expected exactly 1 deduplicated removed pattern, got %+v", diff.BlockPatterns.Removed)
	}
}

func TestDiffConfigs_BotDefenseAndCrawlers(t *testing.T) {
	base := CreateConfig()
	base.BotDefenseLevel = "off"
	base.BlockAIBots = false

	candidate := CreateConfig()
	candidate.BotDefenseLevel = "standard"
	candidate.BlockAIBots = true
	candidate.DetectBrowserImpersonation = true
	candidate.BlockScriptClients = true
	candidate.HoneypotTrapPaths = []string{"/hidden-trap"}
	candidate.BlockedASNs = []string{"AS64501"}
	candidate.BlockUserAgents = []string{"(?i)BadCrawler"}

	diff := DiffConfigs(base, candidate, "base.json", "candidate.json")
	if !diff.HasDifferences {
		t.Fatal("expected differences for bot defense changes")
	}
	if diff.Impact != DiffImpactHardened {
		t.Errorf("expected HARDENED impact, got %s", diff.Impact)
	}
	if _, ok := diff.Properties["botDefenseLevel"]; !ok {
		t.Errorf("expected diff in botDefenseLevel")
	}
	if _, ok := diff.Properties["blockAIBots"]; !ok {
		t.Errorf("expected diff in blockAIBots")
	}
	if len(diff.HoneypotTrapPaths.Added) != 1 {
		t.Errorf("expected 1 added honeypot trap path, got %d", len(diff.HoneypotTrapPaths.Added))
	}
	if len(diff.BlockedASNs.Added) != 1 {
		t.Errorf("expected 1 added blocked ASN, got %d", len(diff.BlockedASNs.Added))
	}
	if len(diff.BlockUserAgents.Added) != 1 {
		t.Errorf("expected 1 added block user agent, got %d", len(diff.BlockUserAgents.Added))
	}

	// Relaxing case: disable bot defense in candidate
	diffRelax := DiffConfigs(candidate, base, "candidate.json", "base.json")
	if !diffRelax.HasDifferences {
		t.Fatal("expected differences when bot defense is disabled")
	}
	if diffRelax.Impact != DiffImpactRelaxed {
		t.Errorf("expected RELAXED impact, got %s", diffRelax.Impact)
	}
}

func TestDiffConfigs_ASNMethodAndIPCanonicalization(t *testing.T) {
	base := CreateConfig()
	base.AllowedASNs = []string{"AS64500", "as64502"}
	base.BlockedASNs = []string{"64501"}
	base.Methods = []string{"GET", "post"}
	base.AllowedIPs = []string{"192.0.2.1", "[2001:db8::1]"}
	base.TrustedProxies = []string{"10.0.0.1"}

	candidate := CreateConfig()
	// Equivalent representations with different casing, prefixing, and bracketing
	candidate.AllowedASNs = []string{"64500", "AS64502"}
	candidate.BlockedASNs = []string{"AS64501"}
	candidate.Methods = []string{"get", "POST"}
	candidate.AllowedIPs = []string{"192.0.2.1", "2001:db8::1"}
	candidate.TrustedProxies = []string{"10.0.0.1"}

	diff := DiffConfigs(base, candidate, "base.json", "candidate.json")
	if diff.HasDifferences {
		t.Errorf("expected no differences between semantically identical ASN, Method, and IP representations, got %+v", diff)
	}
	if diff.Impact != DiffImpactNeutral {
		t.Errorf("expected NEUTRAL impact, got %s", diff.Impact)
	}

	// Now introduce an actual change
	candidate.AllowedASNs = append(candidate.AllowedASNs, "AS64503")
	diffActual := DiffConfigs(base, candidate, "base.json", "candidate.json")
	if !diffActual.HasDifferences {
		t.Error("expected difference when new ASN is added")
	}
	if len(diffActual.AllowedASNs.Added) != 1 || diffActual.AllowedASNs.Added[0] != "AS64503" {
		t.Errorf("expected added AS64503, got %+v", diffActual.AllowedASNs.Added)
	}
}

func TestDiffConfigs_AllowedIPsAndAllowPatternsImpact(t *testing.T) {
	// 1. Adding allowedIps relaxes posture
	base := CreateConfig()
	candidateRelaxed := CreateConfig()
	candidateRelaxed.AllowedIPs = []string{"10.0.0.0/8"}
	diff1 := DiffConfigs(base, candidateRelaxed, "base.json", "candidate.json")
	if diff1.Impact != DiffImpactRelaxed {
		t.Errorf("expected adding allowedIps to be RELAXED, got %s", diff1.Impact)
	}

	// 2. Removing allowedIps hardens posture
	diff2 := DiffConfigs(candidateRelaxed, base, "base.json", "candidate.json")
	if diff2.Impact != DiffImpactHardened {
		t.Errorf("expected removing allowedIps to be HARDENED, got %s", diff2.Impact)
	}

	// 3. Removing allowPatterns hardens posture
	baseAllow := CreateConfig()
	baseAllow.AllowPatterns = []string{"/safe/bypass"}
	diff3 := DiffConfigs(baseAllow, base, "base.json", "candidate.json")
	if diff3.Impact != DiffImpactHardened {
		t.Errorf("expected removing allowPatterns to be HARDENED, got %s", diff3.Impact)
	}

	// 4. Adding ASNDB hardens posture
	candASN := CreateConfig()
	candASN.ASNDB = "/data/GeoLite2-ASN.mmdb"
	diff4 := DiffConfigs(base, candASN, "base.json", "candidate.json")
	if diff4.Impact != DiffImpactHardened {
		t.Errorf("expected configuring ASNDB to be HARDENED, got %s", diff4.Impact)
	}

	// 5. Removing ASNDB relaxes posture
	diff5 := DiffConfigs(candASN, base, "base.json", "candidate.json")
	if diff5.Impact != DiffImpactRelaxed {
		t.Errorf("expected removing ASNDB to be RELAXED, got %s", diff5.Impact)
	}

	// 6. Adding CheckHeaders hardens posture
	candHeaders := CreateConfig()
	candHeaders.CheckHeaders = []string{"X-Forwarded-Prefix"}
	diff6 := DiffConfigs(base, candHeaders, "base.json", "candidate.json")
	if diff6.Impact != DiffImpactHardened {
		t.Errorf("expected adding checkHeaders to be HARDENED, got %s", diff6.Impact)
	}

	// 7. Removing CheckHeaders relaxes posture
	diff7 := DiffConfigs(candHeaders, base, "base.json", "candidate.json")
	if diff7.Impact != DiffImpactRelaxed {
		t.Errorf("expected removing checkHeaders to be RELAXED, got %s", diff7.Impact)
	}

	// 8. Adding Methods hardens posture
	baseMethods := CreateConfig()
	baseMethods.Methods = []string{"GET"}
	candMethods := CreateConfig()
	candMethods.Methods = []string{"GET", "POST"}
	diff8 := DiffConfigs(baseMethods, candMethods, "base.json", "candidate.json")
	if diff8.Impact != DiffImpactHardened {
		t.Errorf("expected adding methods to be HARDENED, got %s", diff8.Impact)
	}

	// 9. Removing Methods relaxes posture
	diff9 := DiffConfigs(candMethods, baseMethods, "base.json", "candidate.json")
	if diff9.Impact != DiffImpactRelaxed {
		t.Errorf("expected removing methods to be RELAXED, got %s", diff9.Impact)
	}
}
