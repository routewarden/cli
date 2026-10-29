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
	candidate.CheckBody = false // relaxed
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
