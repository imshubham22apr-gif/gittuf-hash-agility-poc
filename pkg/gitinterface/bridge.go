// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package gitinterface - GAP-1 Hash Agility Extension
// File: bridge.go
//
// Implements the Genesis Bridge — a cryptographically signed record that
// links the last SHA-1 RSL tip to the first SHA-256 RSL tip, enabling
// verifiers to establish a chain of trust across the hash epoch boundary.
//
// Commitment formula:
//
//	sha256("genesis-bridge|gap1-bridge-v2|sha1|<sha1RSLTip>|<sha1HeadOID>|sha256|<sha256RSLTip>|<sha256HeadOID>|<RFC3339timestamp>")
//
// All four OIDs are committed so that no field can be changed without
// invalidating the digest (and therefore the signature).
//
// The CommitmentDigest is signed using an SSH private key (sshsig format,
// namespace "gittuf-bridge"). The resulting armored signature and the signer's
// raw SSH public key are embedded in the JSON record so that any verifier
// can independently re-derive and check the signature without needing a
// separate allowed_signers file — they only need the bridge JSON itself.
package gitinterface

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // used only for the SHA-1 digest size
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hiddeco/sshsig" //nolint:staticcheck
	"golang.org/x/crypto/ssh"
)

const (
	// bridgeSigNamespace is the sshsig namespace used when signing/verifying
	// the Genesis Bridge commitment digest. Using a distinct namespace prevents
	// signatures created for git commits from being accepted here and vice-versa.
	bridgeSigNamespace = "gittuf-bridge"

	// BridgeSchemaVersion is the only bridge schema accepted by verification.
	// v1 bridges did not commit to the SHA-256 RSL tip and are rejected.
	BridgeSchemaVersion = "gap1-bridge-v2"
)

var (
	// ErrBridgeInvalidHash is returned when either OID in a bridge is malformed.
	ErrBridgeInvalidHash = errors.New("bridge contains an invalid hash OID")

	// ErrBridgeMissingField is returned when a required bridge field is empty.
	ErrBridgeMissingField = errors.New("bridge record is missing a required field")

	// ErrBridgeNotSigned is returned when signature verification is requested
	// but the bridge record carries no embedded signature.
	ErrBridgeNotSigned = errors.New("bridge record has no embedded signature")

	// ErrBridgeSignatureInvalid is returned when the SSH signature over the
	// commitment digest fails verification.
	ErrBridgeSignatureInvalid = errors.New("bridge SSH signature verification failed")

	// ErrBridgeUnsupportedSchema is returned when a bridge record uses a
	// schema version other than BridgeSchemaVersion.
	ErrBridgeUnsupportedSchema = errors.New("unsupported bridge schema version")

	// ErrBridgeInvalidTimestamp is returned when a bridge record carries an
	// unparseable or non-canonical timestamp.
	ErrBridgeInvalidTimestamp = errors.New("bridge contains an invalid or non-RFC3339 timestamp")
)

// GenesisBridgeRecord is the canonical link between a SHA-1 epoch's final
// RSL tip and the SHA-256 epoch's first RSL tip.
//
// JSON fields:
//   - schema_version    — "gap1-bridge-v2"
//   - created_at        — RFC3339 UTC timestamp of migration freeze
//   - sha1_rsl_tip      — final RSL tip in the SHA-1 epoch
//   - sha1_head_oid     — HEAD commit OID in the SHA-1 epoch
//   - sha256_rsl_tip    — first RSL tip in the SHA-256 epoch
//   - sha256_head_oid   — HEAD commit OID in the SHA-256 epoch
//   - commitment_digest — sha256(...) of canonical fields (see formula above)
//   - signature         — sshsig armored signature over commitment_digest (optional)
//   - signer_public_key — raw SSH public key used for signing (optional)
//   - description       — human-readable note
type GenesisBridgeRecord struct {
	SchemaVersion    string    `json:"schema_version"`
	CreatedAt        time.Time `json:"created_at"`
	SHA1RSLTip       string    `json:"sha1_rsl_tip"`
	SHA1HeadOID      string    `json:"sha1_head_oid"`
	SHA256RSLTip     string    `json:"sha256_rsl_tip"`
	SHA256HeadOID    string    `json:"sha256_head_oid"`
	CommitmentDigest string    `json:"commitment_digest"`
	// Signature is the armored sshsig signature over CommitmentDigest bytes,
	// created with the private key corresponding to SignerPublicKey.
	// Empty when the bridge has not been signed yet.
	Signature string `json:"signature,omitempty"`
	// SignerPublicKey is the raw SSH public-key line (e.g. "ssh-ed25519 AAAA...")
	// of the key that produced Signature. Embedded so verifiers need only
	// the bridge JSON — no external allowed_signers file required.
	SignerPublicKey string `json:"signer_public_key,omitempty"`
	// Signatures holds multiple threshold signatures over CommitmentDigest,
	// allowing repositories requiring k-of-n root approvals to verify natively.
	Signatures  []BridgeSignature `json:"signatures,omitempty"`
	Description string            `json:"description"`
}

// BridgeSignature represents an individual cryptographic signature embedded in a Genesis Bridge.
type BridgeSignature struct {
	Signature       string `json:"signature"`
	SignerPublicKey string `json:"signer_public_key"`
}

// BridgeVerificationResult holds the output of VerifyGenesisBridge and
// VerifyGenesisBridgeSignature.
type BridgeVerificationResult struct {
	SHA1RSLTip       string
	SHA256RSLTip     string
	CommitmentOK     bool
	SignatureOK      bool
	SignatureSkipped bool // true when bridge carries no signature
	ErrorDetail      string
}

// NewGenesisBridge creates an unsigned GenesisBridgeRecord.
// Call SignGenesisBridge afterwards to embed a cryptographic signature.
func NewGenesisBridge(
	sha1RSLTip, sha1HeadOID,
	sha256RSLTip, sha256HeadOID string,
) (*GenesisBridgeRecord, error) {
	bridge := &GenesisBridgeRecord{
		SchemaVersion: BridgeSchemaVersion,
		// Truncate to seconds so the in-memory value matches what the
		// RFC3339 commitment and the JSON round-trip preserve.
		CreatedAt:     time.Now().UTC().Truncate(time.Second),
		SHA1RSLTip:    sha1RSLTip,
		SHA1HeadOID:   sha1HeadOID,
		SHA256RSLTip:  sha256RSLTip,
		SHA256HeadOID: sha256HeadOID,
		Description:   "GAP-1 Genesis Bridge: links SHA-1 RSL epoch to SHA-256 RSL epoch for continuous chain of trust",
	}
	if err := validateBridgeFields(bridge); err != nil {
		return nil, err
	}
	bridge.CommitmentDigest = computeBridgeCommitment(bridge)

	return bridge, nil
}

// computeBridgeCommitment returns the canonical commitment digest over every
// identifying field of the bridge.
func computeBridgeCommitment(bridge *GenesisBridgeRecord) string {
	raw := fmt.Sprintf("genesis-bridge|%s|sha1|%s|%s|sha256|%s|%s|%s",
		bridge.SchemaVersion,
		bridge.SHA1RSLTip,
		bridge.SHA1HeadOID,
		bridge.SHA256RSLTip,
		bridge.SHA256HeadOID,
		bridge.CreatedAt.UTC().Format(time.RFC3339),
	)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// validateBridgeFields checks the schema version and that every OID is
// present, hex-encoded, and of the length expected for its epoch (40 hex
// chars for SHA-1, 64 for SHA-256).
func validateBridgeFields(bridge *GenesisBridgeRecord) error {
	if bridge.SchemaVersion != BridgeSchemaVersion {
		return fmt.Errorf("%w: got '%s', want '%s'", ErrBridgeUnsupportedSchema, bridge.SchemaVersion, BridgeSchemaVersion)
	}

	oids := []struct {
		name, value string
		hexLen      int
	}{
		{"sha1_rsl_tip", bridge.SHA1RSLTip, sha1.Size * 2},
		{"sha1_head_oid", bridge.SHA1HeadOID, sha1.Size * 2},
		{"sha256_rsl_tip", bridge.SHA256RSLTip, sha256.Size * 2},
		{"sha256_head_oid", bridge.SHA256HeadOID, sha256.Size * 2},
	}
	for _, oid := range oids {
		if oid.value == "" {
			return fmt.Errorf("%w: %s", ErrBridgeMissingField, oid.name)
		}
		if len(oid.value) != oid.hexLen {
			return fmt.Errorf("%w: %s must be %d hex chars, got %d", ErrBridgeInvalidHash, oid.name, oid.hexLen, len(oid.value))
		}
		if _, err := hex.DecodeString(oid.value); err != nil {
			return fmt.Errorf("%w: %s is not valid hex", ErrBridgeInvalidHash, oid.name)
		}
	}

	if bridge.CreatedAt.IsZero() {
		return fmt.Errorf("%w: created_at timestamp cannot be zero", ErrBridgeInvalidTimestamp)
	}

	return nil
}

// SignGenesisBridge signs the bridge's CommitmentDigest using the provided
// SSH private key (PEM bytes). It embeds the armored sshsig signature and
// the corresponding public key into the record in-place.
//
// The signed payload is exactly the UTF-8 encoding of CommitmentDigest
// (the hex string), so a verifier only needs the bridge JSON to confirm
// both the math and the cryptographic signature.
func SignGenesisBridge(bridge *GenesisBridgeRecord, pemPrivateKeyBytes []byte) error {
	if bridge.CommitmentDigest == "" {
		return fmt.Errorf("%w: CommitmentDigest is empty, cannot sign", ErrBridgeMissingField)
	}

	// Parse private key
	signer, err := ssh.ParsePrivateKey(pemPrivateKeyBytes)
	if err != nil {
		return fmt.Errorf("cannot parse SSH private key: %w", err)
	}

	// Sign the commitment digest bytes using sshsig (SHA-512 hash, gittuf-bridge namespace)
	payload := strings.NewReader(bridge.CommitmentDigest)
	sig, err := sshsig.Sign(payload, signer, sshsig.HashSHA512, bridgeSigNamespace)
	if err != nil {
		return fmt.Errorf("sshsig signing failed: %w", err)
	}

	// Embed armored signature
	armoredSig := string(sshsig.Armor(sig))
	pubKeyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	bridge.Signature = armoredSig
	bridge.SignerPublicKey = pubKeyLine
	bridge.Signatures = []BridgeSignature{
		{Signature: armoredSig, SignerPublicKey: pubKeyLine},
	}

	return nil
}

// AddSignature signs the bridge's CommitmentDigest using an additional SSH private key
// and appends the signature to the record.
func AddSignature(bridge *GenesisBridgeRecord, pemPrivateKeyBytes []byte) error {
	if bridge.CommitmentDigest == "" {
		return fmt.Errorf("%w: CommitmentDigest is empty, cannot sign", ErrBridgeMissingField)
	}

	signer, err := ssh.ParsePrivateKey(pemPrivateKeyBytes)
	if err != nil {
		return fmt.Errorf("cannot parse SSH private key: %w", err)
	}

	payload := strings.NewReader(bridge.CommitmentDigest)
	sig, err := sshsig.Sign(payload, signer, sshsig.HashSHA512, bridgeSigNamespace)
	if err != nil {
		return fmt.Errorf("sshsig signing failed: %w", err)
	}

	armoredSig := string(sshsig.Armor(sig))
	pubKeyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	if bridge.Signature == "" {
		bridge.Signature = armoredSig
		bridge.SignerPublicKey = pubKeyLine
	}

	bridge.Signatures = append(bridge.Signatures, BridgeSignature{
		Signature:       armoredSig,
		SignerPublicKey: pubKeyLine,
	})

	return nil
}

// VerifyGenesisBridge verifies only the internal commitment math.
// It does NOT verify the cryptographic signature.
// Use VerifyGenesisBridgeSignature for full verification.
func VerifyGenesisBridge(bridge *GenesisBridgeRecord) *BridgeVerificationResult {
	result := &BridgeVerificationResult{
		SHA1RSLTip:   bridge.SHA1RSLTip,
		SHA256RSLTip: bridge.SHA256RSLTip,
	}

	if err := validateBridgeFields(bridge); err != nil {
		result.ErrorDetail = err.Error()
		return result
	}

	expected := computeBridgeCommitment(bridge)
	if expected == bridge.CommitmentDigest {
		result.CommitmentOK = true
	} else {
		result.CommitmentOK = false
		result.ErrorDetail = fmt.Sprintf(
			"commitment mismatch: got %s, expected %s",
			bridge.CommitmentDigest, expected,
		)
	}

	return result
}

// VerifyGenesisBridgeSignature performs FULL verification:
//  1. Re-derives the commitment digest (math check)
//  2. Parses the embedded signer public key from the bridge record
//  3. Verifies the sshsig signature over CommitmentDigest using that key
//     (namespace: "gittuf-bridge", hash: SHA-512)
//
// If the bridge carries no signature, it returns ErrBridgeNotSigned.
// The caller (VerifyRefCrossEpoch) must decide whether to treat unsigned
// bridges as acceptable — by default they are rejected in secure mode.
func VerifyGenesisBridgeSignature(bridge *GenesisBridgeRecord) (*BridgeVerificationResult, error) {
	result := &BridgeVerificationResult{
		SHA1RSLTip:   bridge.SHA1RSLTip,
		SHA256RSLTip: bridge.SHA256RSLTip,
	}

	// Step 1: Commitment math check
	mathResult := VerifyGenesisBridge(bridge)
	result.CommitmentOK = mathResult.CommitmentOK
	if !result.CommitmentOK {
		result.ErrorDetail = mathResult.ErrorDetail
		return result, fmt.Errorf("%w: %s", ErrBridgeSignatureInvalid, result.ErrorDetail)
	}

	// Step 2: Check that signatures are present
	var sigs []BridgeSignature
	if bridge.Signature != "" && bridge.SignerPublicKey != "" {
		sigs = append(sigs, BridgeSignature{
			Signature:       bridge.Signature,
			SignerPublicKey: bridge.SignerPublicKey,
		})
	}
	for _, s := range bridge.Signatures {
		if s.Signature != bridge.Signature || s.SignerPublicKey != bridge.SignerPublicKey {
			sigs = append(sigs, s)
		}
	}
	if len(sigs) == 0 {
		result.SignatureSkipped = true
		return result, ErrBridgeNotSigned
	}

	// Step 3-5: Verify each signature against the CommitmentDigest
	for i, s := range sigs {
		if s.Signature == "" || s.SignerPublicKey == "" {
			result.ErrorDetail = fmt.Sprintf("signature entry %d is missing signature or public key", i)
			return result, fmt.Errorf("%w: %s", ErrBridgeSignatureInvalid, result.ErrorDetail)
		}

		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.SignerPublicKey))
		if err != nil {
			result.ErrorDetail = fmt.Sprintf("cannot parse embedded signer public key (%d): %v", i, err)
			return result, fmt.Errorf("%w: %s", ErrBridgeSignatureInvalid, result.ErrorDetail)
		}

		sig, err := sshsig.Unarmor([]byte(s.Signature))
		if err != nil {
			result.ErrorDetail = fmt.Sprintf("cannot parse bridge signature (%d): %v", i, err)
			return result, fmt.Errorf("%w: %s", ErrBridgeSignatureInvalid, result.ErrorDetail)
		}

		err = sshsig.Verify(
			bytes.NewReader([]byte(bridge.CommitmentDigest)),
			sig,
			pubKey,
			sshsig.HashSHA512,
			bridgeSigNamespace,
		)
		if err != nil {
			result.ErrorDetail = fmt.Sprintf("sshsig verification failed (%d): %v", i, err)
			return result, fmt.Errorf("%w: %s", ErrBridgeSignatureInvalid, result.ErrorDetail)
		}
	}

	result.SignatureOK = true
	return result, nil
}

// WriteGenesisBridge serialises a GenesisBridgeRecord to a JSON file.
func WriteGenesisBridge(bridge *GenesisBridgeRecord, outputPath string) error {
	data, err := json.MarshalIndent(bridge, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal bridge record: %w", err)
	}
	return os.WriteFile(outputPath, data, 0o644)
}

// LoadGenesisBridge reads and parses a GenesisBridgeRecord from disk.
func LoadGenesisBridge(path string) (*GenesisBridgeRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read bridge record: %w", err)
	}
	var b GenesisBridgeRecord
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("cannot parse bridge record: %w", err)
	}
	return &b, nil
}

// GenesisBridgeSummary returns a human-readable summary for CLI output.
func GenesisBridgeSummary(b *GenesisBridgeRecord) string {
	sigStatus := "unsigned"
	if b.Signature != "" {
		sigStatus = "signed ✔"
	}
	return fmt.Sprintf(
		"Genesis Bridge (GAP-1)\n"+
			"  Created:        %s\n"+
			"  SHA-1 RSL Tip:  %s\n"+
			"  SHA-1 HEAD:     %s\n"+
			"  SHA-256 RSL Tip:%s\n"+
			"  SHA-256 HEAD:   %s\n"+
			"  Commitment:     %s\n"+
			"  Signature:      %s\n",
		b.CreatedAt.Format(time.RFC3339),
		b.SHA1RSLTip,
		b.SHA1HeadOID,
		b.SHA256RSLTip,
		b.SHA256HeadOID,
		b.CommitmentDigest,
		sigStatus,
	)
}
