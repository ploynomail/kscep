package main

import (
	"crypto"
	"encoding/hex"
	"strings"
	"testing"
)

func TestValidateFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		wantErr     bool
	}{
		{
			name:        "Valid fingerprint without spaces or colons",
			fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr:     false,
		},
		{
			name:        "Valid fingerprint with spaces",
			fingerprint: "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855",
			wantErr:     false,
		},
		{
			name:        "Valid fingerprint with colons",
			fingerprint: "e3:b0:c4:42:98:fc:1c:14:9a:fb:f4:c8:99:6f:b9:24:27:ae:41:e4:64:9b:93:4c:a4:95:99:1b:78:52:b8:55",
			wantErr:     false,
		},
		{
			name:        "Invalid fingerprint length",
			fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
			wantErr:     true,
		},
		{
			name:        "Invalid fingerprint characters",
			fingerprint: "invalidfingerprint",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := validateFingerprint(tt.fingerprint)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				expectedHash, _ := hex.DecodeString(strings.NewReplacer(" ", "", ":", "").Replace(tt.fingerprint))
				if !crypto.SHA256.Available() || len(hash) != len(expectedHash) {
					t.Errorf("validateFingerprint() hash = %v, expectedHash %v", hash, expectedHash)
				}
			}
		})
	}
}
