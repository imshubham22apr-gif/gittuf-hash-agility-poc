// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package rsl

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gittuf/gittuf/pkg/customfields"
	"github.com/gittuf/gittuf/pkg/githash"
	"github.com/gittuf/gittuf/pkg/gitstore"
)

const (
	// GenesisBridgeEntryHeader is the commit message header for a GAP-1 Genesis Bridge entry.
	GenesisBridgeEntryHeader = "RSL Genesis Bridge Entry"

	BridgeSchemaVersionKey    = "schemaVersion"
	PriorEpochHashAlgoKey     = "priorEpochHashAlgo"
	PriorEpochRSLTipKey       = "priorEpochRSLTip"
	PriorEpochHeadOIDKey      = "priorEpochHeadOID"
	CurrentEpochRSLTipKey     = "currentEpochRSLTip"
	CurrentEpochHeadOIDKey    = "currentEpochHeadOID"
	CommitmentDigestKey       = "commitmentDigest"
	FrozenTimestampKey        = "frozenTimestamp"
	BridgeSignatureKey        = "bridgeSignature"
	BridgeSignerPublicKeyKey  = "bridgeSignerPublicKey"
	BridgeDescriptionKey      = "bridgeDescription"
	defaultPriorEpochHashAlgo = "sha1"
)

var (
	// ErrInvalidGenesisBridgeEntry is returned when a genesis bridge entry is malformed.
	ErrInvalidGenesisBridgeEntry = errors.New("invalid RSL genesis bridge entry")
)

// GenesisBridgeEntry is an RSL entry that records a signed GAP-1 Genesis Bridge
// in the current (SHA-256) epoch's RSL. It links the prior (SHA-1) epoch's
// final RSL tip and HEAD to the current epoch's RSL tip and HEAD at migration
// time. It satisfies the rsl.Entry interface.
//
// The entry stores the complete signed bridge record so that a verifier can
// re-derive the commitment and check the signature from the RSL alone. Being
// in the RSL does not make the entry trusted: verifiers must still check the
// commitment, the signature, and that the signer is a root key.
type GenesisBridgeEntry struct {
	// ID is the Git commit ID of this entry in the current repository's object format.
	ID githash.Hash

	// SchemaVersion is the bridge schema version (e.g. "gap1-bridge-v2").
	SchemaVersion string

	// PriorEpochHashAlgo is the algorithm of the prior epoch (e.g. "sha1").
	PriorEpochHashAlgo string

	// PriorEpochRSLTip is the final RSL tip OID of the prior epoch.
	PriorEpochRSLTip string

	// PriorEpochHeadOID is the tip commit of the default branch in the prior epoch.
	PriorEpochHeadOID string

	// CurrentEpochRSLTip is the current epoch's RSL tip the bridge commits to.
	// A correctly recorded entry is this entry's parent in the RSL.
	CurrentEpochRSLTip string

	// CurrentEpochHeadOID is the migrated tip commit in the new epoch.
	CurrentEpochHeadOID string

	// CommitmentDigest is the SHA-256 digest binding the two epochs.
	CommitmentDigest string

	// FrozenTimestamp is the RFC3339 UTC timestamp recorded at migration freeze.
	FrozenTimestamp string

	// Signature is the base64 encoding of the armored sshsig signature over
	// CommitmentDigest.
	Signature string

	// SignerPublicKey is the authorized_keys formatted SSH public key that
	// produced Signature.
	SignerPublicKey string

	// Description is a human-readable note.
	Description string

	// Number contains the strictly increasing RSL sequence number.
	Number uint64

	// CustomFields holds any user/application metadata.
	CustomFields CustomFields
}

func (e *GenesisBridgeEntry) GetID() githash.Hash {
	return e.ID
}

func (e *GenesisBridgeEntry) GetNumber() uint64 {
	return e.Number
}

func (e *GenesisBridgeEntry) GetCustomField(key string) (string, bool) {
	value, has := e.CustomFields[key]
	return value, has
}

func (e *GenesisBridgeEntry) Commit(storer gitstore.Storer, sign bool) error {
	if err := e.setEntryNumber(storer); err != nil {
		return err
	}

	message, err := e.createCommitMessage(true)
	if err != nil {
		return err
	}

	return commitEntry(storer, message, sign)
}

func (e *GenesisBridgeEntry) CommitUsingSpecificKey(storer gitstore.Storer, signingKeyBytes []byte) error {
	if err := e.setEntryNumber(storer); err != nil {
		return err
	}

	message, err := e.createCommitMessage(true)
	if err != nil {
		return err
	}

	return commitEntryUsingSpecificKey(storer, message, signingKeyBytes)
}

func (e *GenesisBridgeEntry) setEntryNumber(storer gitstore.Storer) error {
	latestEntry, err := GetLatestEntry(storer)
	if err == nil {
		e.Number = latestEntry.GetNumber() + 1
	} else {
		if errors.Is(err, ErrRSLEntryNotFound) {
			e.Number = 1
		} else {
			return err
		}
	}
	return nil
}

func (e *GenesisBridgeEntry) createCommitMessage(includeNumber bool) (string, error) {
	if e.PriorEpochRSLTip == "" || e.PriorEpochHeadOID == "" || e.CurrentEpochHeadOID == "" {
		return "", ErrInvalidGenesisBridgeEntry
	}

	priorEpochHashAlgo := e.PriorEpochHashAlgo
	if priorEpochHashAlgo == "" {
		priorEpochHashAlgo = defaultPriorEpochHashAlgo
	}

	lines := []string{GenesisBridgeEntryHeader, ""}
	appendField := func(key, value string) {
		if value != "" {
			lines = append(lines, fmt.Sprintf("%s: %s", key, value))
		}
	}
	appendField(BridgeSchemaVersionKey, e.SchemaVersion)
	appendField(PriorEpochHashAlgoKey, priorEpochHashAlgo)
	appendField(PriorEpochRSLTipKey, e.PriorEpochRSLTip)
	appendField(PriorEpochHeadOIDKey, e.PriorEpochHeadOID)
	appendField(CurrentEpochRSLTipKey, e.CurrentEpochRSLTip)
	appendField(CurrentEpochHeadOIDKey, e.CurrentEpochHeadOID)
	appendField(CommitmentDigestKey, e.CommitmentDigest)
	appendField(FrozenTimestampKey, e.FrozenTimestamp)
	appendField(BridgeSignatureKey, e.Signature)
	appendField(BridgeSignerPublicKeyKey, e.SignerPublicKey)
	appendField(BridgeDescriptionKey, e.Description)

	for _, line := range lines[2:] {
		if strings.ContainsAny(line, "\r\n") {
			return "", fmt.Errorf("%w: field values must be single-line", ErrInvalidGenesisBridgeEntry)
		}
	}

	if includeNumber && e.Number > 0 {
		lines = append(lines, fmt.Sprintf("%s: %d", NumberKey, e.Number))
	}

	lines, err := appendCustomFieldLines(lines, e.CustomFields)
	if err != nil {
		return "", err
	}

	return strings.Join(lines, "\n"), nil
}

// parseGenesisBridgeEntryText parses a Genesis Bridge commit message into a GenesisBridgeEntry.
func parseGenesisBridgeEntryText(id githash.Hash, text string) (*GenesisBridgeEntry, error) {
	body, err := entryBody(text, GenesisBridgeEntryHeader)
	if err != nil {
		return nil, err
	}

	entry := &GenesisBridgeEntry{ID: id}

	for _, line := range body {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, ErrInvalidRSLEntry
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)

		switch key {
		case BridgeSchemaVersionKey:
			entry.SchemaVersion = value
		case PriorEpochHashAlgoKey:
			entry.PriorEpochHashAlgo = value
		case PriorEpochRSLTipKey:
			entry.PriorEpochRSLTip = value
		case PriorEpochHeadOIDKey:
			entry.PriorEpochHeadOID = value
		case CurrentEpochRSLTipKey:
			entry.CurrentEpochRSLTip = value
		case CurrentEpochHeadOIDKey:
			entry.CurrentEpochHeadOID = value
		case CommitmentDigestKey:
			entry.CommitmentDigest = value
		case FrozenTimestampKey:
			entry.FrozenTimestamp = value
		case BridgeSignatureKey:
			entry.Signature = value
		case BridgeSignerPublicKeyKey:
			entry.SignerPublicKey = value
		case BridgeDescriptionKey:
			entry.Description = value
		case NumberKey:
			if err := setNumber(&entry.Number, value); err != nil {
				return nil, err
			}
		default:
			if strings.HasPrefix(key, customfields.Prefix) {
				setCustomField(&entry.CustomFields, key, value)
			}
		}
	}

	if entry.PriorEpochRSLTip == "" || entry.PriorEpochHeadOID == "" || entry.CurrentEpochHeadOID == "" {
		return nil, ErrInvalidRSLEntry
	}

	if entry.FrozenTimestamp != "" {
		parsedTime, err := time.Parse(time.RFC3339, entry.FrozenTimestamp)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid RFC3339 frozen timestamp '%s': %w", ErrInvalidGenesisBridgeEntry, entry.FrozenTimestamp, err)
		}
		// Canonicalize to UTC RFC3339 representation
		entry.FrozenTimestamp = parsedTime.UTC().Format(time.RFC3339)
	}

	return entry, nil
}
