// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gittuf

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/gittuf/gittuf/pkg/rsl"
)

var (
	// ErrBridgeNotInLedger is returned when cross-epoch verification is asked
	// to use the RSL's Genesis Bridge but the RSL has none.
	ErrBridgeNotInLedger = errors.New("no Genesis Bridge entry in the RSL")

	// ErrBridgeAlreadyRecorded is returned when recording a Genesis Bridge in
	// an RSL that already has one.
	ErrBridgeAlreadyRecorded = errors.New("the RSL already has a Genesis Bridge entry")

	// ErrMultipleBridgesInLedger is returned when the RSL has more than one
	// Genesis Bridge entry, which makes the epoch boundary ambiguous.
	ErrMultipleBridgesInLedger = errors.New("the RSL has more than one Genesis Bridge entry")

	// ErrBridgeRSLTipMoved is returned when recording a bridge whose
	// sha256_rsl_tip is not the current RSL tip.
	ErrBridgeRSLTipMoved = errors.New("the bridge's sha256_rsl_tip is not the current RSL tip")

	// ErrBridgeLedgerPlacement is returned when a Genesis Bridge entry is not
	// recorded directly on top of the RSL tip it commits to.
	ErrBridgeLedgerPlacement = errors.New("genesis bridge entry is not recorded directly on top of its sha256_rsl_tip")

	// ErrBridgeLedgerMismatch is returned when a bridge file and the RSL's
	// Genesis Bridge entry describe different bridges.
	ErrBridgeLedgerMismatch = errors.New("bridge file does not match the Genesis Bridge entry in the RSL")
)

// RecordGenesisBridge appends the signed bridge to this (SHA-256) repository's
// RSL as a GenesisBridgeEntry. The bridge must have a valid commitment and
// signature, be signed by a root key of this repository, commit to the current
// RSL tip (so the entry lands directly on top of the state it describes), and
// be the first bridge in the RSL.
func (r *Repository) RecordGenesisBridge(ctx context.Context, bridge *gitinterface.GenesisBridgeRecord, signCommit bool) error {
	if _, err := gitinterface.VerifyGenesisBridgeSignature(bridge); err != nil {
		return err
	}

	if err := r.VerifyGenesisBridgeSigner(ctx, bridge); err != nil {
		return err
	}

	existing, err := r.findGenesisBridgeEntries()
	if err != nil {
		return err
	}
	if len(existing) != 0 {
		return fmt.Errorf("%w (entry %s)", ErrBridgeAlreadyRecorded, existing[0].GetID().String())
	}

	rslTip, err := r.r.GetReference(rsl.Ref)
	if err != nil {
		return fmt.Errorf("cannot read RSL tip: %w", err)
	}
	if rslTip.String() != bridge.SHA256RSLTip {
		return fmt.Errorf("%w: RSL tip is %s, bridge commits to %s; create the bridge again with --sha256-rsl %s", ErrBridgeRSLTipMoved, rslTip.String(), bridge.SHA256RSLTip, rslTip.String())
	}

	return bridgeRecordToEntry(bridge).Commit(r.r, signCommit)
}

// VerifyGenesisBridgeSigner checks that the bridge's signer is a root key of
// this repository's current policy. It does not check the signature itself;
// see gitinterface.VerifyGenesisBridgeSignature.
func (r *Repository) VerifyGenesisBridgeSigner(ctx context.Context, bridge *gitinterface.GenesisBridgeRecord) error {
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyRef)
	if err != nil {
		return fmt.Errorf("cannot load policy: %w", err)
	}

	return verifyBridgeSignersMeetThreshold(state, bridge)
}

// loadCrossEpochBridge returns the bridge to verify and, if the RSL has one,
// the RSL's Genesis Bridge entry. With no bridge file, the RSL entry is the
// bridge. With a bridge file and an RSL entry, both must describe the same
// bridge.
func (r *Repository) loadCrossEpochBridge(bridgeFilePath string) (*gitinterface.GenesisBridgeRecord, *rsl.GenesisBridgeEntry, error) {
	entries, err := r.findGenesisBridgeEntries()
	if err != nil {
		return nil, nil, err
	}
	if len(entries) > 1 {
		return nil, nil, fmt.Errorf("%w: found %d", ErrMultipleBridgesInLedger, len(entries))
	}

	var ledgerEntry *rsl.GenesisBridgeEntry
	if len(entries) == 1 {
		ledgerEntry = entries[0]
	}

	if bridgeFilePath == "" {
		if ledgerEntry == nil {
			return nil, nil, fmt.Errorf("%w: record one with 'gittuf bridge record' or pass --bridge-file", ErrBridgeNotInLedger)
		}
		bridge, err := bridgeEntryToRecord(ledgerEntry)
		if err != nil {
			return nil, nil, err
		}
		return bridge, ledgerEntry, nil
	}

	bridge, err := gitinterface.LoadGenesisBridge(bridgeFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot load genesis bridge file '%s': %w", bridgeFilePath, err)
	}
	if ledgerEntry != nil && ledgerEntry.CommitmentDigest != bridge.CommitmentDigest {
		return nil, nil, fmt.Errorf("%w: file commitment %s, RSL entry %s commitment %s", ErrBridgeLedgerMismatch, bridge.CommitmentDigest, ledgerEntry.GetID().String(), ledgerEntry.CommitmentDigest)
	}

	return bridge, ledgerEntry, nil
}

// verifyBridgeLedgerPlacement checks that the RSL entry's parent is the RSL
// tip the bridge commits to.
func (r *Repository) verifyBridgeLedgerPlacement(entry *rsl.GenesisBridgeEntry) error {
	parent, err := rsl.GetParentForEntry(r.r, entry)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBridgeLedgerPlacement, err)
	}
	if parent.GetID().String() != entry.CurrentEpochRSLTip {
		return fmt.Errorf("%w: parent is %s, bridge commits to %s", ErrBridgeLedgerPlacement, parent.GetID().String(), entry.CurrentEpochRSLTip)
	}

	return nil
}

// findGenesisBridgeEntries walks the whole RSL and returns every Genesis Bridge
// entry, newest first.
func (r *Repository) findGenesisBridgeEntries() ([]*rsl.GenesisBridgeEntry, error) {
	entry, err := rsl.GetLatestEntry(r.r)
	if err != nil {
		if errors.Is(err, rsl.ErrRSLEntryNotFound) {
			return nil, nil
		}
		return nil, err
	}

	var bridges []*rsl.GenesisBridgeEntry
	for {
		if bridge, isBridge := entry.(*rsl.GenesisBridgeEntry); isBridge {
			bridges = append(bridges, bridge)
		}

		entry, err = rsl.GetParentForEntry(r.r, entry)
		if err != nil {
			if errors.Is(err, rsl.ErrRSLEntryNotFound) {
				return bridges, nil
			}
			return nil, err
		}
	}
}

func bridgeRecordToEntry(bridge *gitinterface.GenesisBridgeRecord) *rsl.GenesisBridgeEntry {
	return &rsl.GenesisBridgeEntry{
		SchemaVersion:       bridge.SchemaVersion,
		PriorEpochHashAlgo:  "sha1",
		PriorEpochRSLTip:    bridge.SHA1RSLTip,
		PriorEpochHeadOID:   bridge.SHA1HeadOID,
		CurrentEpochRSLTip:  bridge.SHA256RSLTip,
		CurrentEpochHeadOID: bridge.SHA256HeadOID,
		CommitmentDigest:    bridge.CommitmentDigest,
		FrozenTimestamp:     bridge.CreatedAt.UTC().Format(time.RFC3339),
		Signature:           base64.StdEncoding.EncodeToString([]byte(bridge.Signature)),
		SignerPublicKey:     bridge.SignerPublicKey,
		Description:         bridge.Description,
	}
}

func bridgeEntryToRecord(entry *rsl.GenesisBridgeEntry) (*gitinterface.GenesisBridgeRecord, error) {
	if entry.PriorEpochHashAlgo != "sha1" {
		return nil, fmt.Errorf("%w: unsupported prior epoch hash algorithm '%s'", rsl.ErrInvalidGenesisBridgeEntry, entry.PriorEpochHashAlgo)
	}

	createdAt, err := time.Parse(time.RFC3339, entry.FrozenTimestamp)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid frozen timestamp: %w", rsl.ErrInvalidGenesisBridgeEntry, err)
	}

	signature, err := base64.StdEncoding.DecodeString(entry.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature encoding: %w", rsl.ErrInvalidGenesisBridgeEntry, err)
	}

	record := &gitinterface.GenesisBridgeRecord{
		SchemaVersion:    entry.SchemaVersion,
		CreatedAt:        createdAt.UTC(),
		SHA1RSLTip:       entry.PriorEpochRSLTip,
		SHA1HeadOID:      entry.PriorEpochHeadOID,
		SHA256RSLTip:     entry.CurrentEpochRSLTip,
		SHA256HeadOID:    entry.CurrentEpochHeadOID,
		CommitmentDigest: entry.CommitmentDigest,
		Signature:        string(signature),
		SignerPublicKey:  entry.SignerPublicKey,
		Description:      entry.Description,
	}
	if record.Signature != "" && record.SignerPublicKey != "" {
		record.Signatures = []gitinterface.BridgeSignature{
			{Signature: record.Signature, SignerPublicKey: record.SignerPublicKey},
		}
	}
	return record, nil
}
