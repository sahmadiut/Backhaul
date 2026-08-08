package transport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sahmadiut/backhaul/config"
)

func TestHTTPSNormalRequestReceivesNginxWelcomePage(t *testing.T) {
	server := &HttpTransport{
		config:       &HttpConfig{Mode: config.HTTPS},
		expectedAuth: "Bearer secret",
	}

	request := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	if server.isBackhaulUpgradeRequest(request) {
		t.Fatal("an ordinary browser request must not be treated as a Backhaul upgrade")
	}

	recorder := httptest.NewRecorder()
	serveNginxWelcomePage(recorder)
	response := recorder.Result()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if response.Header.Get("Server") != "nginx" {
		t.Fatalf("Server header = %q, want nginx", response.Header.Get("Server"))
	}
	if !strings.Contains(recorder.Body.String(), "Welcome to nginx!") {
		t.Fatal("response does not contain the Nginx welcome page")
	}
}

func TestBackhaulUpgradeRequestIsRecognized(t *testing.T) {
	server := &HttpTransport{expectedAuth: "Bearer secret"}
	request := httptest.NewRequest(http.MethodGet, "https://example.com/tunnel/42", nil)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("Upgrade", "backhaul")

	if !server.isBackhaulUpgradeRequest(request) {
		t.Fatal("valid Backhaul upgrade request was not recognized")
	}
}
