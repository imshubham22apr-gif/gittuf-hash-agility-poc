// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package rsl

import (
	"testing"

	"github.com/gittuf/gittuf/pkg/githash"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestGenesisBridgeEntry() *GenesisBridgeEntry {
	return &GenesisBridgeEntry{
		SchemaVersion:       "gap1-bridge-v2",
		PriorEpochHashAlgo:  "sha1",
		PriorEpochRSLTip:    "1e73ba090dc2cd3a6166866ab81f36ae8965d532",
		PriorEpochHeadOID:   "984eb14257364893a4b23a18cb1d01945cc8e448",
		CurrentEpochRSLTip:  "15e5447c49ca157f0682662881ec097cf1c62164a235421ca9f9a6a0080920cd",
		CurrentEpochHeadOID: "1757f76331894752532184969f97d5541d7d5f4aa83e4b12ca6a0b67ae6b5071",
		CommitmentDigest:    "8d7e734d1c314e441297f6a99f8eaf86aebbf85ddf3be04de8512c3c528a1ab5",
		FrozenTimestamp:     "2026-10-06T10:00:00Z",
		Signature:           "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KZmFrZQotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
		SignerPublicKey:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINGhGukHwHgZBvcawTsHlKlOkMtQCcvvcJBeY/RkjxDy",
		Description:         "GAP-1 Genesis Bridge: links SHA-1 RSL epoch to SHA-256 RSL epoch",
	}
}

func TestGenesisBridgeEntryMessageRoundTrip(t *testing.T) {
	t.Parallel()

	entry := newTestGenesisBridgeEntry()
	entry.Number = 7

	msg, err := entry.createCommitMessage(true)
	require.Nil(t, err)

	id, err := githash.NewHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	require.Nil(t, err)
	parsed, err := parseGenesisBridgeEntryText(id, msg)
	require.Nil(t, err)

	entry.ID = id
	assert.Equal(t, entry, parsed)
}

func TestGenesisBridgeEntryValidation(t *testing.T) {
	t.Parallel()

	tests := map[string]func(e *GenesisBridgeEntry){
		"missing prior RSL tip":    func(e *GenesisBridgeEntry) { e.PriorEpochRSLTip = "" },
		"missing prior head":       func(e *GenesisBridgeEntry) { e.PriorEpochHeadOID = "" },
		"missing current head":     func(e *GenesisBridgeEntry) { e.CurrentEpochHeadOID = "" },
		"multi-line signature":     func(e *GenesisBridgeEntry) { e.Signature = "line1\nline2" },
		"multi-line description":   func(e *GenesisBridgeEntry) { e.Description = "a\r\nb" },
		"newline-injected rsl tip": func(e *GenesisBridgeEntry) { e.PriorEpochRSLTip += "\nnumber: 99" },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			entry := newTestGenesisBridgeEntry()
			mutate(entry)
			_, err := entry.createCommitMessage(true)
			assert.ErrorIs(t, err, ErrInvalidGenesisBridgeEntry)
		})
	}
}

func TestGenesisBridgeEntryCommitAndLoad(t *testing.T) {
	t.Parallel()

	repo := gitinterface.CreateTestGitRepository(t, t.TempDir(), false)
	require.Nil(t, NewReferenceEntry("refs/heads/main", gitinterface.ZeroHash).Commit(repo, false))

	_, err := GetLatestGenesisBridgeEntry(repo)
	assert.ErrorIs(t, err, ErrRSLEntryNotFound)

	entry := newTestGenesisBridgeEntry()
	require.Nil(t, entry.Commit(repo, false))
	require.Nil(t, NewReferenceEntry("refs/heads/main", gitinterface.ZeroHash).Commit(repo, false))

	loaded, err := GetLatestGenesisBridgeEntry(repo)
	require.Nil(t, err)

	assert.Equal(t, uint64(2), loaded.Number)
	assert.Equal(t, entry.PriorEpochRSLTip, loaded.PriorEpochRSLTip)
	assert.Equal(t, entry.CurrentEpochRSLTip, loaded.CurrentEpochRSLTip)
	assert.Equal(t, entry.Signature, loaded.Signature)
	assert.Equal(t, entry.SignerPublicKey, loaded.SignerPublicKey)

	// Reference-updater lookups skip the bridge entry.
	latest, _, err := GetLatestReferenceUpdaterEntry(repo, ForReference("refs/heads/main"))
	require.Nil(t, err)
	assert.Equal(t, uint64(3), latest.GetNumber())
}
