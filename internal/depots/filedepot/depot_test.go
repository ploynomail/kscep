package filedepot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/magiconair/properties/assert"
)

var dir = "./testdata"

func TestNewFileDepot(t *testing.T) {

	depot, err := NewFileDepot(dir)
	if err != nil {
		t.Fatalf("NewFileDepot() error = %v", err)
	}
	if depot == nil {
		t.Fatalf("NewFileDepot() returned nil depot")
	}

	// Test the depot directory is not exist
	depot, err = NewFileDepot(dir + "/notexist")
	if err == nil {
		t.Fatalf("NewFileDepot() did not return an error for non-existent directory")
	}
}

func TestFileDepot_CA(t *testing.T) {
	depot, err := NewFileDepot(dir)
	if err != nil {
		t.Fatalf("NewFileDepot() error = %v", err)
	}

	// Generate a test certificate and key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// Write the certificate and key to files
	certPath := dir + "/test.pem"
	keyPath := dir + "/test.key"
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	defer os.Remove(certPath)
	defer os.Remove(keyPath)
	// Test the CA method
	certs, key, err := depot.CA([]byte(""), "test")
	if err != nil {
		t.Fatalf("CA() error = %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("CA() returned %d certificates, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "test" {
		t.Fatalf("CA() returned certificate with CommonName = %v, want test", certs[0].Subject.CommonName)
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Fatalf("CA() returned key of type %T, want *rsa.PrivateKey", key)
	}

	// Test the CA file is not exist
	os.Remove(certPath)
	certs, key, err = depot.CA([]byte(""), "test")
	if err != nil {
		assert.Equal(t, err.Error(), "stat testdata/test.pem: no such file or directory")
	}

	// Test the CA file format is invalid
	if err := os.WriteFile(certPath, []byte("invalid"), 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	certs, key, err = depot.CA([]byte(""), "test")
	if err != nil {
		assert.Equal(t, err.Error(), "PEM decode failed")
	}

	// Test the CA key format is invalid
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("invalid"), 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	certs, key, err = depot.CA([]byte(""), "test")
	if err != nil {
		assert.Equal(t, err.Error(), "PEM decode failed")
	}
}
func TestFileDepot_Put(t *testing.T) {
	certPath := dir + "/test.1.pem"
	defer os.Remove(certPath)
	depot, err := NewFileDepot(dir)
	if err != nil {
		t.Fatalf("NewFileDepot() error = %v", err)
	}

	// Generate a test certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Test the Put method
	err = depot.Put("test", cert)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Verify the certificate file was created

	if _, err := os.ReadFile(certPath); err != nil {
		t.Fatalf("Failed to read cert file: %v", err)
	}

	// Verify the certificate data
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read cert file: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode PEM block containing certificate")
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}
	if parsedCert.Subject.CommonName != "test" {
		t.Fatalf("Put() stored certificate with CommonName = %v, want test", parsedCert.Subject.CommonName)
	}
}
func TestFileDepot_Serial(t *testing.T) {
	serialPath := dir + "/serial"
	defer os.Remove(serialPath)
	depot, err := NewFileDepot(dir)
	if err != nil {
		t.Fatalf("NewFileDepot() error = %v", err)
	}

	// Test the Serial method when the serial file does not exist
	serial, err := depot.Serial()
	if err != nil {
		t.Fatalf("Serial() error = %v", err)
	}
	if serial.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("Serial() = %v, want %v", serial, big.NewInt(2))
	}

	// Test the Serial method when the serial file exists
	serial, err = depot.Serial()
	if err != nil {
		t.Fatalf("Serial() error = %v", err)
	}
	if serial.Cmp(big.NewInt(3)) != 0 {
		t.Fatalf("Serial() = %v, want %v", serial, big.NewInt(3))
	}

	// Verify the serial file content

	data, err := os.ReadFile(serialPath)
	if err != nil {
		t.Fatalf("Failed to read serial file: %v", err)
	}
	serialStr := strings.TrimSpace(string(data))
	expectedSerial := fmt.Sprintf("%x", big.NewInt(3).Bytes())
	if serialStr != expectedSerial {
		t.Fatalf("Serial file content = %v, want %v", serialStr, expectedSerial)
	}
}
func TestFileDepot_HasCN(t *testing.T) {
	depot, err := NewFileDepot(dir)
	if err != nil {
		t.Fatalf("NewFileDepot() error = %v", err)
	}

	// Generate a test certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Write the certificate to the depot
	err = depot.Put("test", cert)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Test HasCN with allowTime = 0 and revokeOldCertificate = false
	exists, err := depot.HasCN("test", 0, cert, false)
	if err != nil {
		t.Fatalf("HasCN() error = %v", err)
	}
	if !exists {
		t.Fatalf("HasCN() = %v, want true", exists)
	}

	// Test HasCN with allowTime = 0 and revokeOldCertificate = true
	exists, err = depot.HasCN("test", 0, cert, true)
	if err != nil {
		t.Fatalf("HasCN() error = %v", err)
	}
	if !exists {
		t.Fatalf("HasCN() = %v, want true", exists)
	}

	// Test HasCN with allowTime > 0 and revokeOldCertificate = false
	exists, err = depot.HasCN("test", 1, cert, false)
	if err != nil {
		t.Fatalf("HasCN() error = %v", err)
	}
	if !exists {
		t.Fatalf("HasCN() = %v, want true", exists)
	}

	// Test HasCN with allowTime > 0 and revokeOldCertificate = true
	exists, err = depot.HasCN("test", 1, cert, true)
	if err != nil {
		t.Fatalf("HasCN() error = %v", err)
	}
	if !exists {
		t.Fatalf("HasCN() = %v, want true", exists)
	}
	os.Remove(dir + "/test.1.pem")
	// Test HasCN with a different certificate
	template.Subject.CommonName = "test2"
	certDER, err = x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Write the new certificate to the depot
	err = depot.Put("test2", cert)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Test HasCN with the new certificate
	exists, err = depot.HasCN("test2", 0, cert, false)
	if err != nil {
		t.Fatalf("HasCN() error = %v", err)
	}
	if !exists {
		t.Fatalf("HasCN() = %v, want true", exists)
	}
	os.Remove(dir + "/test2.1.pem")
}
