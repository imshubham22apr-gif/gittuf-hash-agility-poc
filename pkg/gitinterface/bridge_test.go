// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	testBridgeSHA1RSL    = "aaa000111222333444555666777888999aaa0001"
	testBridgeSHA1Head   = "bbb000111222333444555666777888999bbb0001"
	testBridgeSHA256RSL  = "ccc000111222333444555666777888999ccc000111222333444555666777888c"
	testBridgeSHA256Head = "ddd000111222333444555666777888999ddd000111222333444555666777888d"
)

func newTestBridge(t *testing.T) *GenesisBridgeRecord {
	t.Helper()

	bridge, err := NewGenesisBridge(testBridgeSHA1RSL, testBridgeSHA1Head, testBridgeSHA256RSL, testBridgeSHA256Head)
	require.Nil(t, err)
	return bridge
}

// newTestSSHKey returns a PEM-encoded OpenSSH ed25519 private key.
func newTestSSHKey(t *testing.T) []byte {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	require.Nil(t, err)
	return pem.EncodeToMemory(block)
}

func TestNewGenesisBridge(t *testing.T) {
	t.Parallel()

	bridge := newTestBridge(t)

	assert.Equal(t, BridgeSchemaVersion, bridge.SchemaVersion)
	assert.Equal(t, testBridgeSHA1RSL, bridge.SHA1RSLTip)
	assert.Equal(t, testBridgeSHA1Head, bridge.SHA1HeadOID)
	assert.Equal(t, testBridgeSHA256RSL, bridge.SHA256RSLTip)
	assert.Equal(t, testBridgeSHA256Head, bridge.SHA256HeadOID)
	assert.Len(t, bridge.CommitmentDigest, 64)
}

func TestNewGenesisBridgeInvalidFields(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		sha1RSL, sha1Head, sha256RSL, sha256Head string
		expectedErr                              error
	}{
		"empty sha1 rsl tip":           {"", testBridgeSHA1Head, testBridgeSHA256RSL, testBridgeSHA256Head, ErrBridgeMissingField},
		"empty sha256 rsl tip":         {testBridgeSHA1RSL, testBridgeSHA1Head, "", testBridgeSHA256Head, ErrBridgeMissingField},
		"empty sha1 head":              {testBridgeSHA1RSL, "", testBridgeSHA256RSL, testBridgeSHA256Head, ErrBridgeMissingField},
		"empty sha256 head":            {testBridgeSHA1RSL, testBridgeSHA1Head, testBridgeSHA256RSL, "", ErrBridgeMissingField},
		"sha256 value in sha1 field":   {testBridgeSHA256RSL, testBridgeSHA1Head, testBridgeSHA256RSL, testBridgeSHA256Head, ErrBridgeInvalidHash},
		"sha1 value in sha256 field":   {testBridgeSHA1RSL, testBridgeSHA1Head, testBridgeSHA1RSL, testBridgeSHA256Head, ErrBridgeInvalidHash},
		"non-hex sha1 head":            {testBridgeSHA1RSL, strings.Repeat("z", 40), testBridgeSHA256RSL, testBridgeSHA256Head, ErrBridgeInvalidHash},
		"truncated sha256 head":        {testBridgeSHA1RSL, testBridgeSHA1Head, testBridgeSHA256RSL, testBridgeSHA256Head[:63], ErrBridgeInvalidHash},
		"overlong sha256 rsl tip (68)": {testBridgeSHA1RSL, testBridgeSHA1Head, testBridgeSHA256RSL + "0000", testBridgeSHA256Head, ErrBridgeInvalidHash},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := NewGenesisBridge(test.sha1RSL, test.sha1Head, test.sha256RSL, test.sha256Head)
			assert.ErrorIs(t, err, test.expectedErr)
		})
	}
}

func TestVerifyGenesisBridge(t *testing.T) {
	t.Parallel()

	result := VerifyGenesisBridge(newTestBridge(t))
	assert.True(t, result.CommitmentOK, result.ErrorDetail)
}

// TestVerifyGenesisBridgeTampered checks that changing any single committed
// field invalidates the commitment. Before gap1-bridge-v2, sha256_rsl_tip was
// not committed and could be changed undetected.
func TestVerifyGenesisBridgeTampered(t *testing.T) {
	t.Parallel()

	tamper := map[string]func(b *GenesisBridgeRecord){
		"sha1_rsl_tip":    func(b *GenesisBridgeRecord) { b.SHA1RSLTip = strings.Repeat("1", 40) },
		"sha1_head_oid":   func(b *GenesisBridgeRecord) { b.SHA1HeadOID = strings.Repeat("1", 40) },
		"sha256_rsl_tip":  func(b *GenesisBridgeRecord) { b.SHA256RSLTip = strings.Repeat("0", 64) },
		"sha256_head_oid": func(b *GenesisBridgeRecord) { b.SHA256HeadOID = strings.Repeat("0", 64) },
		"created_at":      func(b *GenesisBridgeRecord) { b.CreatedAt = b.CreatedAt.Add(1e9) },
	}

	for field, apply := range tamper {
		t.Run(field, func(t *testing.T) {
			t.Parallel()

			bridge := newTestBridge(t)
			apply(bridge)

			result := VerifyGenesisBridge(bridge)
			assert.False(t, result.CommitmentOK, "tampering with %s was not detected", field)
		})
	}
}

func TestVerifyGenesisBridgeRejectsOldSchema(t *testing.T) {
	t.Parallel()

	bridge := newTestBridge(t)
	bridge.SchemaVersion = "gap1-bridge-v1"

	result := VerifyGenesisBridge(bridge)
	assert.False(t, result.CommitmentOK)
	assert.Contains(t, result.ErrorDetail, ErrBridgeUnsupportedSchema.Error())
}

func TestSignAndVerifyGenesisBridgeSignature(t *testing.T) {
	t.Parallel()

	t.Run("valid signature round-trips through JSON", func(t *testing.T) {
		t.Parallel()

		bridge := newTestBridge(t)
		require.Nil(t, SignGenesisBridge(bridge, newTestSSHKey(t)))

		path := filepath.Join(t.TempDir(), "bridge.json")
		require.Nil(t, WriteGenesisBridge(bridge, path))
		loaded, err := LoadGenesisBridge(path)
		require.Nil(t, err)

		result, err := VerifyGenesisBridgeSignature(loaded)
		assert.Nil(t, err)
		assert.True(t, result.CommitmentOK)
		assert.True(t, result.SignatureOK)
	})

	t.Run("unsigned bridge", func(t *testing.T) {
		t.Parallel()

		result, err := VerifyGenesisBridgeSignature(newTestBridge(t))
		assert.ErrorIs(t, err, ErrBridgeNotSigned)
		assert.True(t, result.SignatureSkipped)
	})

	t.Run("field tampered after signing", func(t *testing.T) {
		t.Parallel()

		bridge := newTestBridge(t)
		require.Nil(t, SignGenesisBridge(bridge, newTestSSHKey(t)))
		bridge.SHA256RSLTip = strings.Repeat("0", 64)

		_, err := VerifyGenesisBridgeSignature(bridge)
		assert.ErrorIs(t, err, ErrBridgeSignatureInvalid)
	})

	t.Run("signer key swapped for another key", func(t *testing.T) {
		t.Parallel()

		bridge := newTestBridge(t)
		require.Nil(t, SignGenesisBridge(bridge, newTestSSHKey(t)))

		other := newTestBridge(t)
		require.Nil(t, SignGenesisBridge(other, newTestSSHKey(t)))
		bridge.SignerPublicKey = other.SignerPublicKey

		_, err := VerifyGenesisBridgeSignature(bridge)
		assert.ErrorIs(t, err, ErrBridgeSignatureInvalid)
	})

	t.Run("signature from a different bridge", func(t *testing.T) {
		t.Parallel()

		key := newTestSSHKey(t)
		bridge := newTestBridge(t)
		require.Nil(t, SignGenesisBridge(bridge, key))

		other, err := NewGenesisBridge(testBridgeSHA1RSL, testBridgeSHA1Head, strings.Repeat("e", 64), testBridgeSHA256Head)
		require.Nil(t, err)
		other.Signature = bridge.Signature
		other.SignerPublicKey = bridge.SignerPublicKey

		_, err = VerifyGenesisBridgeSignature(other)
		assert.ErrorIs(t, err, ErrBridgeSignatureInvalid)
	})

	t.Run("multiple threshold signatures round-trip and verify", func(t *testing.T) {
		t.Parallel()

		key1 := newTestSSHKey(t)
		key2 := newTestSSHKey(t)

		bridge := newTestBridge(t)
		require.Nil(t, SignGenesisBridge(bridge, key1))
		require.Nil(t, AddSignature(bridge, key2))

		assert.Len(t, bridge.Signatures, 2)

		path := filepath.Join(t.TempDir(), "multi-bridge.json")
		require.Nil(t, WriteGenesisBridge(bridge, path))
		loaded, err := LoadGenesisBridge(path)
		require.Nil(t, err)

		result, err := VerifyGenesisBridgeSignature(loaded)
		assert.Nil(t, err)
		assert.True(t, result.CommitmentOK)
		assert.True(t, result.SignatureOK)
	})
}

func TestWriteAndLoadGenesisBridge(t *testing.T) {
	t.Parallel()

	bridge := newTestBridge(t)
	path := filepath.Join(t.TempDir(), "bridge.json")
	require.Nil(t, WriteGenesisBridge(bridge, path))

	loaded, err := LoadGenesisBridge(path)
	require.Nil(t, err)
	assert.Equal(t, bridge, loaded)
	assert.True(t, VerifyGenesisBridge(loaded).CommitmentOK)
}

func TestGenesisBridgeSummary(t *testing.T) {
	t.Parallel()

	summary := GenesisBridgeSummary(newTestBridge(t))
	assert.Contains(t, summary, testBridgeSHA1RSL)
	assert.Contains(t, summary, testBridgeSHA256RSL)
	assert.Contains(t, summary, "unsigned")
}
