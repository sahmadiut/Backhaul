package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectUnsupportedECH(t *testing.T) {
	for _, content := range []string{
		"[client]\ntransport='http'\nech=true\n",
		"[server]\ntransport='httpsws'\nech=true\n",
		"[server]\ntransport='https'\nech=true\nech_key='missing'\n",
	} {
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatal("invalid ECH configuration accepted")
		}
	}
}
