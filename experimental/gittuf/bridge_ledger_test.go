// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gittuf

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/gittuf/gittuf/internal/common"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/gittuf/gittuf/pkg/rsl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadBridge creates, signs and loads a bridge for the fixture's current
// coordinates.
func (f *crossEpochFixture) loadBridge(t *testing.T, signingKey []byte, sha256RSLTip string) *gitinterface.GenesisBridgeRecord {
	t.Helper()

	path := f.writeBridge(t, signingKey, f.sha1RSLTip, f.sha1Head, sha256RSLTip, f.sha256Head)
	bridge, err := gitinterface.LoadGenesisBridge(path)
	require.Nil(t, err)
	return bridge
}

// writeBridgeRecord writes an existing bridge to a file and returns its path.
func (f *crossEpochFixture) writeBridgeRecord(t *testing.T, bridge *gitinterface.GenesisBridgeRecord) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "bridge.json")
	require.Nil(t, gitinterface.WriteGenesisBridge(bridge, path))
	return path
}

// addRSLEntry appends a valid reference entry for main, moving the RSL tip.
func addRSLEntry(t *testing.T, repo *Repository, headOID string) {
	t.Helper()

	head, err := gitinterface.NewHash(headOID)
	require.Nil(t, err)
	common.CreateTestRSLReferenceEntryCommit(t, repo.r, rsl.NewReferenceEntry(crossEpochRef, head), gpgKeyBytes)
}

func TestGenesisBridgeInLedger(t *testing.T) {
	f := newCrossEpochFixture(t)

	t.Run("record then verify from the RSL", func(t *testing.T) {
		repo := f.copySHA256Repo(t)
		require.Nil(t, repo.RecordGenesisBridge(testCtx, f.loadBridge(t, rootKeyBytes, f.sha256RSLTip), false))

		entries, err := repo.findGenesisBridgeEntries()
		require.Nil(t, err)
		require.Len(t, entries, 1)

		assert.Nil(t, repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, "", f.sha1RepoPath))

		// Ordinary verification is unaffected by the bridge entry.
		assert.Nil(t, repo.VerifyRef(testCtx, crossEpochRef))

		// New RSL entries after the bridge are fine.
		addRSLEntry(t, repo, f.sha256Head)
		assert.Nil(t, repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, "", f.sha1RepoPath))
	})

	t.Run("bridge file must match the RSL entry", func(t *testing.T) {
		repo := f.copySHA256Repo(t)
		recorded := f.loadBridge(t, rootKeyBytes, f.sha256RSLTip)
		require.Nil(t, repo.RecordGenesisBridge(testCtx, recorded, false))

		matching := f.writeBridgeRecord(t, recorded)
		assert.Nil(t, repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, matching, f.sha1RepoPath))

		// A different, also root-signed bridge (later timestamp).
		time.Sleep(1100 * time.Millisecond)
		other := f.writeBridge(t, rootKeyBytes, f.sha1RSLTip, f.sha1Head, f.sha256RSLTip, f.sha256Head)
		err := repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, other, f.sha1RepoPath)
		assert.ErrorIs(t, err, ErrBridgeLedgerMismatch)
	})

	t.Run("no bridge in the RSL and no file", func(t *testing.T) {
		repo := f.copySHA256Repo(t)
		err := repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, "", f.sha1RepoPath)
		assert.ErrorIs(t, err, ErrBridgeNotInLedger)
	})

	t.Run("record refuses a second bridge", func(t *testing.T) {
		repo := f.copySHA256Repo(t)
		require.Nil(t, repo.RecordGenesisBridge(testCtx, f.loadBridge(t, rootKeyBytes, f.sha256RSLTip), false))

		tip, err := repo.r.GetReference(rsl.Ref)
		require.Nil(t, err)
		err = repo.RecordGenesisBridge(testCtx, f.loadBridge(t, rootKeyBytes, tip.String()), false)
		assert.ErrorIs(t, err, ErrBridgeAlreadyRecorded)
	})

	t.Run("record refuses a bridge not signed by a root key", func(t *testing.T) {
		repo := f.copySHA256Repo(t)
		err := repo.RecordGenesisBridge(testCtx, f.loadBridge(t, newUnauthorizedSSHKey(t), f.sha256RSLTip), false)
		assert.ErrorIs(t, err, ErrBridgeSignerNotAuthorized)

		entries, err := repo.findGenesisBridgeEntries()
		require.Nil(t, err)
		assert.Empty(t, entries)
	})

	t.Run("record refuses a bridge whose sha256_rsl_tip is not the RSL tip", func(t *testing.T) {
		repo := f.copySHA256Repo(t)
		addRSLEntry(t, repo, f.sha256Head)

		err := repo.RecordGenesisBridge(testCtx, f.loadBridge(t, rootKeyBytes, f.sha256RSLTip), false)
		assert.ErrorIs(t, err, ErrBridgeRSLTipMoved)
	})

	// The remaining cases write entries straight into the RSL, bypassing
	// RecordGenesisBridge, to check that verification does not trust an entry
	// just because it is in the RSL.

	t.Run("forged entry written directly to the RSL", func(t *testing.T) {
		repo := f.copySHA256Repo(t)
		forged := f.loadBridge(t, newUnauthorizedSSHKey(t), f.sha256RSLTip)
		require.Nil(t, bridgeRecordToEntry(forged).Commit(repo.r, false))

		err := repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, "", f.sha1RepoPath)
		assert.ErrorIs(t, err, ErrBridgeSignerNotAuthorized)
	})

	t.Run("entry tampered after signing", func(t *testing.T) {
		repo := f.copySHA256Repo(t)
		entry := bridgeRecordToEntry(f.loadBridge(t, rootKeyBytes, f.sha256RSLTip))
		entry.PriorEpochHeadOID = f.sha1RSLTip
		require.Nil(t, entry.Commit(repo.r, false))

		err := repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, "", f.sha1RepoPath)
		assert.ErrorIs(t, err, gitinterface.ErrBridgeSignatureInvalid)
	})

	t.Run("entry not placed on its sha256_rsl_tip", func(t *testing.T) {
		repo := f.copySHA256Repo(t)
		bridge := f.loadBridge(t, rootKeyBytes, f.sha256RSLTip)
		addRSLEntry(t, repo, f.sha256Head)
		require.Nil(t, bridgeRecordToEntry(bridge).Commit(repo.r, false))

		err := repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, "", f.sha1RepoPath)
		assert.ErrorIs(t, err, ErrBridgeLedgerPlacement)
	})

	t.Run("two bridge entries in the RSL", func(t *testing.T) {
		repo := f.copySHA256Repo(t)
		bridge := f.loadBridge(t, rootKeyBytes, f.sha256RSLTip)
		require.Nil(t, bridgeRecordToEntry(bridge).Commit(repo.r, false))
		require.Nil(t, bridgeRecordToEntry(bridge).Commit(repo.r, false))

		err := repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, "", f.sha1RepoPath)
		assert.ErrorIs(t, err, ErrMultipleBridgesInLedger)
	})

	t.Run("exported signer check", func(t *testing.T) {
		assert.Nil(t, f.sha256Repo.VerifyGenesisBridgeSigner(testCtx, f.loadBridge(t, rootKeyBytes, f.sha256RSLTip)))
		err := f.sha256Repo.VerifyGenesisBridgeSigner(testCtx, f.loadBridge(t, newUnauthorizedSSHKey(t), f.sha256RSLTip))
		assert.ErrorIs(t, err, ErrBridgeSignerNotAuthorized)
	})
}

func TestGenesisBridgeEntryConversionRoundTrip(t *testing.T) {
	t.Parallel()

	bridge, err := gitinterface.NewGenesisBridge(
		"aaa000111222333444555666777888999aaa0001",
		"bbb000111222333444555666777888999bbb0001",
		"ccc000111222333444555666777888999ccc000111222333444555666777888c",
		"ddd000111222333444555666777888999ddd000111222333444555666777888d",
	)
	require.Nil(t, err)
	require.Nil(t, gitinterface.SignGenesisBridge(bridge, newUnauthorizedSSHKey(t)))

	back, err := bridgeEntryToRecord(bridgeRecordToEntry(bridge))
	require.Nil(t, err)
	assert.Equal(t, bridge, back)

	_, err = gitinterface.VerifyGenesisBridgeSignature(back)
	assert.Nil(t, err)
}
