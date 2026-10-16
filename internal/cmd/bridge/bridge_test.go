// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/gittuf/gittuf/pkg/gitinterface"
	"golang.org/x/crypto/ssh"
)

func TestBridgeCommands(t *testing.T) {
	cmd := New()
	if cmd.Use != "bridge" {
		t.Errorf("expected Use 'bridge', got %s", cmd.Use)
	}

	subCommands := cmd.Commands()
	if len(subCommands) < 2 {
		t.Fatalf("expected at least 2 subcommands, got %d", len(subCommands))
	}

	foundCreate := false
	foundVerify := false
	foundRecord := false
	foundSign := false
	for _, sc := range subCommands {
		if sc.Name() == "create" {
			foundCreate = true
		}
		if sc.Name() == "verify" {
			foundVerify = true
		}
		if sc.Name() == "record" {
			foundRecord = true
		}
		if sc.Name() == "sign" {
			foundSign = true
		}
	}

	if !foundCreate {
		t.Error("expected 'create' subcommand not found")
	}
	if !foundVerify {
		t.Error("expected 'verify' subcommand not found")
	}
	if !foundRecord {
		t.Error("expected 'record' subcommand not found")
	}
	if !foundSign {
		t.Error("expected 'sign' subcommand not found")
	}
}

func TestBridgeSignCommand(t *testing.T) {
	tempDir := t.TempDir()
	bridgePath := filepath.Join(tempDir, "genesis-bridge.json")

	bridge, err := gitinterface.NewGenesisBridge(
		"aaa000111222333444555666777888999aaa0001",
		"bbb000111222333444555666777888999bbb0001",
		"ccc000111222333444555666777888999ccc000111222333444555666777888c",
		"ddd000111222333444555666777888999ddd000111222333444555666777888d",
	)
	if err != nil {
		t.Fatalf("failed to create genesis bridge: %v", err)
	}

	if err := gitinterface.WriteGenesisBridge(bridge, bridgePath); err != nil {
		t.Fatalf("failed to write genesis bridge: %v", err)
	}

	// Create test SSH private key
	keyPath := filepath.Join(tempDir, "id_ed25519")
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatalf("failed to write private key: %v", err)
	}

	// Test sign in-place
	rootCmd := New()
	rootCmd.SetArgs([]string{"sign", "-f", bridgePath, "-k", keyPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("bridge sign execution failed: %v", err)
	}

	loaded, err := gitinterface.LoadGenesisBridge(bridgePath)
	if err != nil {
		t.Fatalf("failed to load signed bridge: %v", err)
	}
	if loaded.Signature == "" {
		t.Errorf("expected signature to be set on bridge record")
	}
	if len(loaded.Signatures) != 1 {
		t.Errorf("expected 1 signature in Signatures slice, got %d", len(loaded.Signatures))
	}

	// Create a second test SSH key and sign again (appending signature)
	keyPath2 := filepath.Join(tempDir, "id_ed25519_2")
	_, privKey2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate second key: %v", err)
	}
	pemBlock2, err := ssh.MarshalPrivateKey(privKey2, "")
	if err != nil {
		t.Fatalf("failed to marshal second private key: %v", err)
	}
	if err := os.WriteFile(keyPath2, pem.EncodeToMemory(pemBlock2), 0o600); err != nil {
		t.Fatalf("failed to write second private key: %v", err)
	}

	rootCmd2 := New()
	rootCmd2.SetArgs([]string{"sign", "-f", bridgePath, "-k", keyPath2})
	if err := rootCmd2.Execute(); err != nil {
		t.Fatalf("bridge co-sign execution failed: %v", err)
	}

	loaded2, err := gitinterface.LoadGenesisBridge(bridgePath)
	if err != nil {
		t.Fatalf("failed to load co-signed bridge: %v", err)
	}
	if len(loaded2.Signatures) != 2 {
		t.Errorf("expected 2 signatures in Signatures slice, got %d", len(loaded2.Signatures))
	}

	// Verify all signatures
	res, err := gitinterface.VerifyGenesisBridgeSignature(loaded2)
	if err != nil {
		t.Fatalf("failed to verify multi-signature bridge: %v", err)
	}
	if !res.CommitmentOK || !res.SignatureOK {
		t.Errorf("expected CommitmentOK and SignatureOK to be true")
	}
}
