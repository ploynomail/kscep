package main

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const fingerprintHashType = crypto.SHA256

func validateFlags(keyPath, serverURL, caFingerprint string, useKeyEnciphermentSelector bool) error {
	if keyPath == "" {
		return errors.New("must specify private key path")
	}
	if serverURL == "" {
		return errors.New("must specify server-url flag parameter")
	}
	_, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server-url flag parameter %s", err)
	}
	if caFingerprint != "" && useKeyEnciphermentSelector {
		return errors.New("ca-fingerprint and key-encipherment-selector can't be used at the same time")
	}
	return nil
}

// validateFingerprint makes sure fingerprint looks like a hash.
// We remove spaces and colons from fingerprint as it may come in various forms:
func validateFingerprint(fingerprint string) (hash []byte, err error) {
	fingerprint = strings.NewReplacer(" ", "", ":", "").Replace(fingerprint)
	hash, err = hex.DecodeString(fingerprint)
	if err != nil {
		return
	}
	if len(hash) != fingerprintHashType.Size() {
		err = fmt.Errorf("invalid %s hash length", fingerprintHashType)
	}
	return
}
