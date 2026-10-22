package ech

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var hostname = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

// Generate creates a new directory exclusively; existing credentials are never replaced.
func Generate(dir, inner, public string) error {
	for _, name := range []string{inner, public} {
		if len(name) > 253 || net.ParseIP(name) != nil {
			return fmt.Errorf("use DNS hostnames for -ech-name and -ech-public-name")
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) > 63 || !hostname.MatchString(label) {
				return fmt.Errorf("invalid DNS hostname %q", name)
			}
		}
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	id := make([]byte, 1)
	if _, err = rand.Read(id); err != nil {
		return err
	}
	body := append(id, 0, 32, 0, 32) // X25519 KEM and public-key length
	body = append(body, key.PublicKey().Bytes()...)
	body = append(body, 0, 4, 0, 1, 0, 1, 0, byte(len(public))) // HKDF-SHA256, AES-128-GCM, maximum name length
	body = append(body, public...)
	body = append(body, 0, 0)
	cfg := []byte{0xfe, 0x0d}
	cfg = binary.BigEndian.AppendUint16(cfg, uint16(len(body)))
	cfg = append(cfg, body...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(cfg)))
	list = append(list, cfg...)
	secret, _ := json.Marshal(keyFile{Config: cfg, PrivateKey: key.Bytes()})
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: inner}, DNSNames: []string{inner, public}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &certKey.PublicKey, certKey)
	if err != nil {
		return err
	}
	private, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("create new ECH directory: %w", err)
	}
	files := map[string][]byte{"ech-key.json": secret, "ech-config.txt": []byte(base64.StdEncoding.EncodeToString(list) + "\n"), "cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}
	for name, data := range files {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return err
		}
	}
	return nil
}
