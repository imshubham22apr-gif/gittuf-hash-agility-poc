// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gittuf

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/gittuf/gittuf/internal/policy"
	sslibssh "github.com/gittuf/gittuf/internal/signerverifier/ssh"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/gittuf/gittuf/pkg/rsl"
	"golang.org/x/crypto/ssh"
)

var (
	// ErrBridgeSignerNotAuthorized is returned when the key that signed a
	// Genesis Bridge is not a root key of the SHA-256 epoch's policy.
	ErrBridgeSignerNotAuthorized = errors.New("genesis bridge signer is not a root key of the SHA-256 epoch policy")

	// ErrBridgeThresholdUnsupported is returned when the SHA-256 epoch's root
	// threshold requires more signatures than a bridge record can carry.
	ErrBridgeThresholdUnsupported = errors.New("genesis bridge carries a single signature but the root threshold is greater than 1")

	// ErrBridgeNotBoundToRepository is returned when the bridge's SHA-256
	// coordinates are not part of the repository being verified.
	ErrBridgeNotBoundToRepository = errors.New("genesis bridge SHA-256 coordinates are not part of this repository")
)

// verifyBridgeSignerIsRoot checks that signerPublicKey (an authorized_keys
// formatted SSH public key, as embedded in the bridge) is one of the root keys
// in the given policy state. The bridge's own embedded key is only trusted once
// it is matched against the root of trust the verifier already relies on.
func verifyBridgeSignerIsRoot(state *policy.State, signerPublicKey string) error {
	rootMetadata, err := state.GetRootMetadata(false)
	if err != nil {
		return fmt.Errorf("cannot load SHA-256 epoch root metadata: %w", err)
	}

	threshold, err := rootMetadata.GetRootThreshold()
	if err != nil {
		return fmt.Errorf("cannot load SHA-256 epoch root threshold: %w", err)
	}
	if threshold > 1 {
		return fmt.Errorf("%w (threshold %d)", ErrBridgeThresholdUnsupported, threshold)
	}

	principals, err := rootMetadata.GetRootPrincipals()
	if err != nil {
		return fmt.Errorf("cannot load SHA-256 epoch root principals: %w", err)
	}

	signerKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signerPublicKey))
	if err != nil {
		return fmt.Errorf("%w: cannot parse signer public key: %w", ErrBridgeSignerNotAuthorized, err)
	}
	signerKeyVal := base64.StdEncoding.EncodeToString(signerKey.Marshal())

	for _, principal := range principals {
		for _, key := range principal.Keys() {
			if key.KeyType == sslibssh.KeyType && key.KeyVal.Public == signerKeyVal {
				return nil
			}
		}
	}

	return fmt.Errorf("%w: %s", ErrBridgeSignerNotAuthorized, ssh.FingerprintSHA256(signerKey))
}

// verifyBridgeBindsRepository checks that the bridge's SHA-256 coordinates
// belong to this repository: the bridge's SHA-256 RSL tip must be the current
// RSL tip or one of its ancestors, and the bridge's SHA-256 HEAD must be the
// tip of refName or one of its ancestors.
func (r *Repository) verifyBridgeBindsRepository(bridge *gitinterface.GenesisBridgeRecord, refName string) error {
	checks := []struct {
		name      string
		ref       string
		bridgeOID string
	}{
		{"sha256_rsl_tip", rsl.Ref, bridge.SHA256RSLTip},
		{"sha256_head_oid", refName, bridge.SHA256HeadOID},
	}

	for _, check := range checks {
		currentTip, err := r.r.GetReference(check.ref)
		if err != nil {
			return fmt.Errorf("%w: cannot read '%s': %w", ErrBridgeNotBoundToRepository, check.ref, err)
		}

		bridgeOID, err := gitinterface.NewHash(check.bridgeOID)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrBridgeNotBoundToRepository, check.name, err)
		}

		tipCommit := currentTip
		if strings.HasPrefix(check.ref, gitinterface.TagRefPrefix) {
			peeled, err := r.r.PeelToCommit(currentTip)
			if err == nil {
				tipCommit = peeled
			}
		}

		knows, err := r.r.KnowsCommit(tipCommit, bridgeOID)
		if err != nil || !knows {
			return fmt.Errorf("%w: bridge %s %s is not reachable from '%s' (%s)", ErrBridgeNotBoundToRepository, check.name, check.bridgeOID, check.ref, currentTip.String())
		}
	}

	return nil
}
