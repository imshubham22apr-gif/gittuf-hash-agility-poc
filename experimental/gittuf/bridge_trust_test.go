// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gittuf

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"

	trustpolicyopts "github.com/gittuf/gittuf/experimental/gittuf/options/trustpolicy"
	"github.com/gittuf/gittuf/internal/common"
	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/signerverifier/gpg"
	sslibssh "github.com/gittuf/gittuf/internal/signerverifier/ssh"
	"github.com/gittuf/gittuf/internal/tuf"
	tufv01 "github.com/gittuf/gittuf/internal/tuf/v01"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/gittuf/gittuf/pkg/rsl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// crossEpochFixture is a SHA-1 repository and a SHA-256 repository, each with
// a gittuf policy protecting main and one verified commit on main.
type crossEpochFixture struct {
	sha256Repo               *Repository
	sha1RepoPath             string
	sha1RSLTip, sha1Head     string
	sha256RSLTip, sha256Head string
	sha256UnrelatedCommitOID string
	bridgeDir                string
}

const crossEpochRef = "refs/heads/main"

// createTestRepositoryWithRSAPolicy matches createTestRepositoryWithPolicy
// (main protected by the GPG key) but uses the RSA root key for the targets
// role too, so the fixture only needs RSA and GPG signing.
func createTestRepositoryWithRSAPolicy(t *testing.T, location string, opts ...gitinterface.TestRepositoryOption) *Repository {
	t.Helper()

	r := createTestRepositoryWithRoot(t, location, opts...)
	signer := setupSSHKeysForSigning(t, rootKeyBytes, rootPubKeyBytes)
	targetsPubKey := tufv01.NewKeyFromSSLibKey(signer.MetadataKey())

	require.Nil(t, r.AddTopLevelTargetsKey(testCtx, signer, targetsPubKey, false, trustpolicyopts.WithRSLEntry()))
	require.Nil(t, r.InitializeTargets(testCtx, signer, policy.TargetsRoleName, false, trustpolicyopts.WithRSLEntry()))

	gpgKeyR, err := gpg.LoadGPGKeyFromBytes(gpgKeyBytes)
	require.Nil(t, err)
	gpgKey := tufv01.NewKeyFromSSLibKey(gpgKeyR)

	require.Nil(t, r.AddPrincipalToTargets(testCtx, signer, policy.TargetsRoleName, []tuf.Principal{gpgKey}, false, trustpolicyopts.WithRSLEntry()))
	require.Nil(t, r.AddDelegation(testCtx, signer, policy.TargetsRoleName, "protect-main", []string{gpgKey.KeyID}, []string{"git:refs/heads/main"}, 1, false, trustpolicyopts.WithRSLEntry()))
	require.Nil(t, policy.Apply(testCtx, r.r, false))

	return r
}

func newCrossEpochFixture(t *testing.T) *crossEpochFixture {
	t.Helper()

	sha1RepoPath := t.TempDir()
	sha1Repo := createTestRepositoryWithRSAPolicy(t, sha1RepoPath, gitinterface.WithObjectFormat(gitinterface.ObjectFormatSHA1))
	sha256Repo := createTestRepositoryWithRSAPolicy(t, "", gitinterface.WithSHA256Format())

	record := func(repo *Repository) (string, string) {
		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo.r, crossEpochRef, 1, gpgKeyBytes)
		entry := rsl.NewReferenceEntry(crossEpochRef, commitIDs[0])
		common.CreateTestRSLReferenceEntryCommit(t, repo.r, entry, gpgKeyBytes)

		rslTip, err := repo.r.GetReference(rsl.Ref)
		require.Nil(t, err)
		return rslTip.String(), commitIDs[0].String()
	}

	f := &crossEpochFixture{sha256Repo: sha256Repo, sha1RepoPath: sha1RepoPath, bridgeDir: t.TempDir()}
	f.sha1RSLTip, f.sha1Head = record(sha1Repo)
	f.sha256RSLTip, f.sha256Head = record(sha256Repo)

	// A real commit in the SHA-256 repository that is not reachable from main
	// or the RSL.
	unrelated := common.AddNTestCommitsToSpecifiedRef(t, sha256Repo.r, "refs/heads/unrelated", 1, gpgKeyBytes)
	f.sha256UnrelatedCommitOID = unrelated[0].String()

	return f
}

// writeBridge creates, signs and writes a bridge for the given coordinates and
// returns its path.
func (f *crossEpochFixture) writeBridge(t *testing.T, signingKey []byte, sha1RSLTip, sha1Head, sha256RSLTip, sha256Head string) string {
	t.Helper()

	bridge, err := gitinterface.NewGenesisBridge(sha1RSLTip, sha1Head, sha256RSLTip, sha256Head)
	require.Nil(t, err)
	require.Nil(t, gitinterface.SignGenesisBridge(bridge, signingKey))

	path := filepath.Join(f.bridgeDir, strings.ReplaceAll(t.Name(), "/", "_")+".json")
	require.Nil(t, gitinterface.WriteGenesisBridge(bridge, path))
	return path
}

func newUnauthorizedSSHKey(t *testing.T) []byte {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	require.Nil(t, err)
	return pem.EncodeToMemory(block)
}

func TestVerifyRefCrossEpoch(t *testing.T) {
	f := newCrossEpochFixture(t)

	t.Run("bridge signed by SHA-256 root key", func(t *testing.T) {
		path := f.writeBridge(t, rootKeyBytes, f.sha1RSLTip, f.sha1Head, f.sha256RSLTip, f.sha256Head)
		assert.Nil(t, f.sha256Repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, path, f.sha1RepoPath))
	})

	t.Run("forged bridge signed by an arbitrary key", func(t *testing.T) {
		path := f.writeBridge(t, newUnauthorizedSSHKey(t), f.sha1RSLTip, f.sha1Head, f.sha256RSLTip, f.sha256Head)
		err := f.sha256Repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, path, f.sha1RepoPath)
		assert.ErrorIs(t, err, ErrBridgeSignerNotAuthorized)
	})

	t.Run("bridge signed by a key that is not in the policy", func(t *testing.T) {
		path := f.writeBridge(t, targetsKeyBytes, f.sha1RSLTip, f.sha1Head, f.sha256RSLTip, f.sha256Head)
		err := f.sha256Repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, path, f.sha1RepoPath)
		assert.ErrorIs(t, err, ErrBridgeSignerNotAuthorized)
	})

	t.Run("sha256 rsl tip not in this repository's RSL", func(t *testing.T) {
		path := f.writeBridge(t, rootKeyBytes, f.sha1RSLTip, f.sha1Head, f.sha256UnrelatedCommitOID, f.sha256Head)
		err := f.sha256Repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, path, f.sha1RepoPath)
		assert.ErrorIs(t, err, ErrBridgeNotBoundToRepository)
	})

	t.Run("sha256 rsl tip does not exist", func(t *testing.T) {
		path := f.writeBridge(t, rootKeyBytes, f.sha1RSLTip, f.sha1Head, strings.Repeat("0", 64), f.sha256Head)
		err := f.sha256Repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, path, f.sha1RepoPath)
		assert.ErrorIs(t, err, ErrBridgeNotBoundToRepository)
	})

	t.Run("sha256 head not an ancestor of the verified ref", func(t *testing.T) {
		path := f.writeBridge(t, rootKeyBytes, f.sha1RSLTip, f.sha1Head, f.sha256RSLTip, f.sha256UnrelatedCommitOID)
		err := f.sha256Repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, path, f.sha1RepoPath)
		assert.ErrorIs(t, err, ErrBridgeNotBoundToRepository)
	})

	t.Run("sha1 rsl tip does not match the SHA-1 repository", func(t *testing.T) {
		path := f.writeBridge(t, rootKeyBytes, f.sha1Head, f.sha1Head, f.sha256RSLTip, f.sha256Head)
		err := f.sha256Repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, path, f.sha1RepoPath)
		assert.ErrorContains(t, err, "does not match bridge record")
	})

	t.Run("sha1 head does not match the verified SHA-1 tip", func(t *testing.T) {
		path := f.writeBridge(t, rootKeyBytes, f.sha1RSLTip, strings.Repeat("1", 40), f.sha256RSLTip, f.sha256Head)
		err := f.sha256Repo.VerifyRefCrossEpoch(testCtx, crossEpochRef, path, f.sha1RepoPath)
		assert.ErrorContains(t, err, "does not match bridge HEAD OID")
	})
}

func TestVerifyBridgeSignerIsRoot(t *testing.T) {
	rootSigner := setupSSHKeysForSigning(t, rootKeyBytes, rootPubKeyBytes)
	rootAuthorizedKey := string(rootPubKeyBytes)

	t.Run("root key is authorized", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")
		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyRef)
		require.Nil(t, err)

		assert.Nil(t, verifyBridgeSignerIsRoot(state, rootAuthorizedKey))
	})

	t.Run("non-root key is rejected", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")
		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyRef)
		require.Nil(t, err)

		assert.ErrorIs(t, verifyBridgeSignerIsRoot(state, string(targetsPubKeyBytes)), ErrBridgeSignerNotAuthorized)
	})

	t.Run("malformed key is rejected", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")
		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyRef)
		require.Nil(t, err)

		assert.ErrorIs(t, verifyBridgeSignerIsRoot(state, "not a key"), ErrBridgeSignerNotAuthorized)
	})

	t.Run("root threshold above one fails closed", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")

		secondKey := tufv01.NewKeyFromSSLibKey(sslibssh.NewKeyFromBytes(t, targetsPubKeyBytes))
		require.Nil(t, r.AddRootKey(testCtx, rootSigner, secondKey, false))
		require.Nil(t, r.UpdateRootThreshold(testCtx, rootSigner, 2, false))
		require.Nil(t, r.StagePolicy(testCtx, "", true, false))

		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		require.Nil(t, err)

		assert.ErrorIs(t, verifyBridgeSignerIsRoot(state, rootAuthorizedKey), ErrBridgeThresholdUnsupported)
	})
}
