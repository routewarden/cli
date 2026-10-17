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
