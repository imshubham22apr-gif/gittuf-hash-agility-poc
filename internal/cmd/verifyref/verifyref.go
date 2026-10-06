// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package verifyref

import (
	"fmt"

	"github.com/gittuf/gittuf/experimental/gittuf"
	verifyopts "github.com/gittuf/gittuf/experimental/gittuf/options/verify"
	"github.com/gittuf/gittuf/internal/dev"
	"github.com/spf13/cobra"
)

type options struct {
	latestOnly    bool
	fromEntry     string
	remoteRefName string
	// GAP-1 cross-epoch verify-ref walk flags
	bridgeFile string
	sha1Repo   string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(
		&o.latestOnly,
		"latest-only",
		false,
		"perform verification against latest entry in the RSL",
	)

	cmd.Flags().StringVar(
		&o.fromEntry,
		"from-entry",
		"",
		fmt.Sprintf("perform verification from specified RSL entry (developer mode only, set %s=1)", dev.DevModeKey),
	)

	cmd.MarkFlagsMutuallyExclusive("latest-only", "from-entry")

	cmd.Flags().StringVar(
		&o.remoteRefName,
		"remote-ref-name",
		"",
		"name of remote reference, if it differs from the local name",
	)

	// GAP-1: cross-epoch verify-ref walk flags
	cmd.Flags().StringVar(
		&o.bridgeFile,
		"bridge-file",
		"",
		"(GAP-1) path to a genesis bridge JSON file; defaults to the Genesis Bridge recorded in the RSL (requires --sha1-repo)",
	)

	cmd.Flags().StringVar(
		&o.sha1Repo,
		"sha1-repo",
		"",
		"(GAP-1) path to the prior SHA-1 epoch repository; enables cross-epoch verification",
	)

	// GAP-1 flags are incompatible with latest-only and from-entry
	cmd.MarkFlagsMutuallyExclusive("bridge-file", "latest-only")
	cmd.MarkFlagsMutuallyExclusive("bridge-file", "from-entry")
	cmd.MarkFlagsMutuallyExclusive("sha1-repo", "latest-only")
	cmd.MarkFlagsMutuallyExclusive("sha1-repo", "from-entry")
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	if o.bridgeFile != "" && o.sha1Repo == "" {
		return fmt.Errorf("--bridge-file requires --sha1-repo")
	}

	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	// GAP-1 cross-epoch verify-ref walk; the bridge comes from --bridge-file
	// or, when that is empty, from the RSL
	if o.sha1Repo != "" {
		return repo.VerifyRefCrossEpoch(
			cmd.Context(),
			args[0],
			o.bridgeFile,
			o.sha1Repo,
			verifyopts.WithOverrideRefName(o.remoteRefName),
		)
	}

	if o.fromEntry != "" {
		if !dev.InDevMode() {
			return dev.ErrNotInDevMode
		}

		return repo.VerifyRefFromEntry(cmd.Context(), args[0], o.fromEntry, verifyopts.WithOverrideRefName(o.remoteRefName))
	}

	opts := []verifyopts.Option{verifyopts.WithOverrideRefName(o.remoteRefName)}
	if o.latestOnly {
		opts = append(opts, verifyopts.WithLatestOnly())
	}
	return repo.VerifyRef(cmd.Context(), args[0], opts...)
}

func New() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:               "verify-ref",
		Short:             "Tools for verifying gittuf policies",
		Args:              cobra.ExactArgs(1),
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
