package inventory_test

import (
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
)

func TestPHPInstallHelpers(t *testing.T) {
	t.Parallel()

	id1 := inventory.ComputeID(inventory.SourceLocal, inventory.SAPICLI, "/usr/bin/php8.3")
	id2 := inventory.ComputeID(inventory.SourceLocal, inventory.SAPICLI, "/usr/bin/php8.3")
	id3 := inventory.ComputeID(inventory.SourceLocal, inventory.SAPIFPM, "/usr/sbin/php-fpm8.3")

	if id1 == "" {
		t.Fatal("ComputeID returned empty string")
	}
	if id1 != id2 {
		t.Fatalf("ComputeID not deterministic: %q != %q", id1, id2)
	}
	if id1 == id3 {
		t.Fatalf("ComputeID collided for different targets: %q == %q", id1, id3)
	}

	inst := inventory.PHPInstall{
		ID:     id1,
		Source: inventory.SourceLocal,
		SAPI:   inventory.SAPICLI,
	}
	inst.AddConfigFile("/etc/php/8.3/cli/php.ini")
	inst.AddConfigFile("/etc/php/8.3/cli/php.ini")
	inst.AddConfigFile("")
	if len(inst.ConfigFiles) != 1 {
		t.Fatalf("ConfigFiles len = %d, want 1", len(inst.ConfigFiles))
	}

	inst.SetIniSetting("session.upload_progress.enabled", "0", "/etc/php/8.3/cli/php.ini")
	if got := inst.IniSettings["session.upload_progress.enabled"]; got != "0" {
		t.Fatalf("IniSettings[session.upload_progress.enabled] = %q, want 0", got)
	}
	if len(inst.Evidence) != 1 {
		t.Fatalf("Evidence len = %d, want 1", len(inst.Evidence))
	}
}
