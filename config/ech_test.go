package config

import (
	"github.com/BurntSushi/toml"
	"testing"
)

func TestECHConfiguration(t *testing.T) {
	var cfg Config
	_, err := toml.Decode(`[server]
transport="https"
ech=true
ech_key="server-key.json"
[client]
transport="https"
ech=true
ech_config="public.txt"
ech_ca="ca.pem"
ech_doh="https://dns.example/resolve"
`, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Server.Enabled || cfg.Server.KeyFile != "server-key.json" || !cfg.Client.Enabled || cfg.Client.ConfigFile != "public.txt" || cfg.Client.CAFile != "ca.pem" || cfg.Client.DoHURL != "https://dns.example/resolve" {
		t.Fatal("ECH configuration not decoded")
	}
	var legacy Config
	if _, err = toml.Decode(`[client]
transport="https"
remote_addr="example.com:443"
`, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Client.Enabled || legacy.Server.Enabled {
		t.Fatal("ECH enabled by default")
	}
}
