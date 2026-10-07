// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"errors"
	"fmt"
	"os"

	"github.com/gittuf/gittuf/experimental/gittuf"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/spf13/cobra"
)

type createOptions struct {
	sha1RSLTip    string
	sha1HeadOID   string
	sha256RSLTip  string
	sha256HeadOID string
	outputFile    string
	signingKeys   []string // paths to SSH private keys for threshold signing
}

func (co *createOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&co.sha1RSLTip, "sha1-rsl", "", "Tip OID of SHA-1 RSL epoch")
	cmd.Flags().StringVar(&co.sha1HeadOID, "sha1-head", "", "Tip OID of SHA-1 repository HEAD")
	cmd.Flags().StringVar(&co.sha256RSLTip, "sha256-rsl", "", "Initial tip OID of SHA-256 RSL epoch")
	cmd.Flags().StringVar(&co.sha256HeadOID, "sha256-head", "", "Initial tip OID of SHA-256 repository HEAD")
	cmd.Flags().StringVarP(&co.outputFile, "output", "o", "genesis-bridge.json", "Output path for the genesis bridge record")
	cmd.Flags().StringSliceVarP(
		&co.signingKeys,
		"signing-key", "k",
		nil,
		"Path(s) to SSH private key (PEM) used to cryptographically sign the bridge commitment digest.\n"+
			"Can be specified multiple times to satisfy multi-key root thresholds.",
	)

	_ = cmd.MarkFlagRequired("sha1-rsl")
	_ = cmd.MarkFlagRequired("sha1-head")
	_ = cmd.MarkFlagRequired("sha256-rsl")
	_ = cmd.MarkFlagRequired("sha256-head")
}

func (co *createOptions) Run(cmd *cobra.Command, _ []string) error {
	cmd.Printf("Creating GAP-1 Genesis Bridge record...\n")

	bridge, err := gitinterface.NewGenesisBridge(
		co.sha1RSLTip,
		co.sha1HeadOID,
		co.sha256RSLTip,
		co.sha256HeadOID,
	)
	if err != nil {
		return fmt.Errorf("failed to create genesis bridge: %w", err)
	}

	// Sign the bridge if signing keys were provided
	if len(co.signingKeys) > 0 {
		for i, keyPath := range co.signingKeys {
			cmd.Printf("Signing bridge commitment with key (%d/%d): %s\n", i+1, len(co.signingKeys), keyPath)
			pemBytes, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("cannot read signing key '%s': %w", keyPath, err)
			}
			if i == 0 {
				if err := gitinterface.SignGenesisBridge(bridge, pemBytes); err != nil {
					return fmt.Errorf("failed to sign genesis bridge: %w", err)
				}
			} else {
				if err := gitinterface.AddSignature(bridge, pemBytes); err != nil {
					return fmt.Errorf("failed to add signature to genesis bridge: %w", err)
				}
			}
		}
		cmd.Printf("✅ Bridge signed successfully (%d signature(s) embedded in JSON)\n", len(co.signingKeys))
	} else {
		cmd.Printf("⚠️  WARNING: Bridge created WITHOUT a signature.\n")
		cmd.Printf("   Use --signing-key <path> to embed an SSH signature.\n")
		cmd.Printf("   Unsigned bridges will be rejected by 'gittuf verify-ref --bridge-file'.\n")
	}

	if err := gitinterface.WriteGenesisBridge(bridge, co.outputFile); err != nil {
		return fmt.Errorf("failed to write genesis bridge file: %w", err)
	}

	cmd.Printf("✅ Genesis Bridge created successfully: %s\n", co.outputFile)
	cmd.Printf("%s\n", gitinterface.GenesisBridgeSummary(bridge))
	return nil
}

type verifyOptions struct {
	bridgeFile string
}

func (vo *verifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&vo.bridgeFile,
		"file",
		"f",
		"genesis-bridge.json",
		"path to genesis bridge JSON file to verify",
	)
}

func (vo *verifyOptions) Run(cmd *cobra.Command, _ []string) error {
	bridge, err := gitinterface.LoadGenesisBridge(vo.bridgeFile)
	if err != nil {
		return fmt.Errorf("failed to load genesis bridge: %w", err)
	}

	cmd.Printf("Verifying Genesis Bridge: %s\n\n", vo.bridgeFile)

	// Full verification: commitment math + SSH signature
	result, err := gitinterface.VerifyGenesisBridgeSignature(bridge)
	if err != nil {
		if result != nil && result.CommitmentOK {
			// Math passed but signature failed/missing
			return fmt.Errorf("❌ Bridge commitment ✔ but signature check FAILED: %w", err)
		}
		return fmt.Errorf("❌ Genesis Bridge verification FAILED: %w", err)
	}

	cmd.Printf("✅ Commitment digest ✔\n")
	cmd.Printf("✅ SSH signature valid for the key embedded in the bridge\n")
	cmd.Printf("   Signer key: %s\n", bridge.SignerPublicKey)
	cmd.Printf("   Commitment: %s\n", bridge.CommitmentDigest)

	// Root authority: when run inside the SHA-256 repository, the signer must
	// be one of its root keys.
	repo, err := gittuf.LoadRepository(".")
	if err == nil {
		err = repo.VerifyGenesisBridgeSigner(cmd.Context(), bridge)
		if err == nil {
			cmd.Printf("✅ Signer is a root key of this repository ✔\n")
			cmd.Printf("\n   For the full cross-epoch check run 'gittuf verify-ref <ref> --sha1-repo <path>'.\n")
			return nil
		}
		if errors.Is(err, gittuf.ErrBridgeSignerNotAuthorized) || errors.Is(err, gittuf.ErrBridgeThresholdUnsupported) {
			return fmt.Errorf("❌ root authority check FAILED: %w", err)
		}
	}

	cmd.Printf("\n⚠️  Root authority NOT checked (%v).\n", err)
	cmd.Printf("   Without that check, anyone can embed their own key. Run this command inside\n")
	cmd.Printf("   the SHA-256 repository, or run 'gittuf verify-ref <ref> --sha1-repo <path>' there.\n")
	return nil
}

type recordOptions struct {
	bridgeFile string
}

func (ro *recordOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&ro.bridgeFile,
		"file",
		"f",
		"genesis-bridge.json",
		"path to the signed genesis bridge JSON file to record",
	)
}

func (ro *recordOptions) Run(cmd *cobra.Command, _ []string) error {
	bridge, err := gitinterface.LoadGenesisBridge(ro.bridgeFile)
	if err != nil {
		return fmt.Errorf("failed to load genesis bridge: %w", err)
	}

	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	if err := repo.RecordGenesisBridge(cmd.Context(), bridge, true); err != nil {
		return fmt.Errorf("❌ failed to record Genesis Bridge in the RSL: %w", err)
	}

	cmd.Printf("✅ Genesis Bridge recorded in the RSL on top of %s\n", bridge.SHA256RSLTip)
	cmd.Printf("   Verify with 'gittuf verify-ref <ref> --sha1-repo <path>'.\n")
	return nil
}

type signOptions struct {
	bridgeFile string
	signingKey string
	outputFile string
}

func (so *signOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&so.bridgeFile,
		"file",
		"f",
		"genesis-bridge.json",
		"path to existing genesis bridge JSON file to sign",
	)
	cmd.Flags().StringVarP(
		&so.signingKey,
		"signing-key",
		"k",
		"",
		"path to SSH private key used to co-sign the bridge record",
	)
	cmd.Flags().StringVarP(
		&so.outputFile,
		"output",
		"o",
		"",
		"optional output path (defaults to updating --file in-place)",
	)

	_ = cmd.MarkFlagRequired("signing-key")
}

func (so *signOptions) Run(cmd *cobra.Command, _ []string) error {
	bridge, err := gitinterface.LoadGenesisBridge(so.bridgeFile)
	if err != nil {
		return fmt.Errorf("failed to load genesis bridge '%s': %w", so.bridgeFile, err)
	}

	pemBytes, err := os.ReadFile(so.signingKey)
	if err != nil {
		return fmt.Errorf("cannot read signing key '%s': %w", so.signingKey, err)
	}

	if bridge.Signature == "" {
		if err := gitinterface.SignGenesisBridge(bridge, pemBytes); err != nil {
			return fmt.Errorf("failed to sign genesis bridge: %w", err)
		}
	} else {
		if err := gitinterface.AddSignature(bridge, pemBytes); err != nil {
			return fmt.Errorf("failed to append signature to genesis bridge: %w", err)
		}
	}

	targetPath := so.outputFile
	if targetPath == "" {
		targetPath = so.bridgeFile
	}

	if err := gitinterface.WriteGenesisBridge(bridge, targetPath); err != nil {
		return fmt.Errorf("failed to write updated genesis bridge: %w", err)
	}

	cmd.Printf("✅ Appended signature to Genesis Bridge (%d total signature(s))\n", len(bridge.Signatures))
	cmd.Printf("   Updated file: %s\n", targetPath)
	return nil
}

func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:               "bridge",
		Short:             "GAP-1 Genesis Bridge tools for cross-epoch verification",
		Long:              "Commands to create and verify cryptographic links between SHA-1 and SHA-256 RSL epochs.",
		DisableAutoGenTag: true,
	}

	// Subcommand: gittuf bridge create
	createOpt := &createOptions{}
	createCmd := &cobra.Command{
		Use:               "create",
		Short:             "Create (and optionally sign) a Genesis Bridge record linking SHA-1 and SHA-256 epochs",
		RunE:              createOpt.Run,
		DisableAutoGenTag: true,
	}
	createOpt.AddFlags(createCmd)
	rootCmd.AddCommand(createCmd)

	// Subcommand: gittuf bridge sign
	signOpt := &signOptions{}
	signCmd := &cobra.Command{
		Use:               "sign",
		Short:             "Append a cryptographic signature to an existing Genesis Bridge record",
		Long:              "Append an SSH signature to an existing Genesis Bridge record. Enables asynchronous multi-party root threshold signing across independent maintainer machines.",
		RunE:              signOpt.Run,
		DisableAutoGenTag: true,
	}
	signOpt.AddFlags(signCmd)
	rootCmd.AddCommand(signCmd)

	// Subcommand: gittuf bridge verify
	verifyOpt := &verifyOptions{}
	verifyCmd := &cobra.Command{
		Use:               "verify",
		Short:             "Check a Genesis Bridge record's commitment, signature and, inside the SHA-256 repository, that the signer is a root key",
		RunE:              verifyOpt.Run,
		DisableAutoGenTag: true,
	}
	verifyOpt.AddFlags(verifyCmd)
	rootCmd.AddCommand(verifyCmd)

	// Subcommand: gittuf bridge record
	recordOpt := &recordOptions{}
	recordCmd := &cobra.Command{
		Use:               "record",
		Short:             "Record a signed Genesis Bridge in this (SHA-256) repository's RSL",
		Long:              "Record a signed Genesis Bridge in this (SHA-256) repository's RSL. The bridge must be signed by a root key of this repository, commit to the current RSL tip, and be the first bridge in the RSL.",
		RunE:              recordOpt.Run,
		DisableAutoGenTag: true,
	}
	recordOpt.AddFlags(recordCmd)
	rootCmd.AddCommand(recordCmd)

	return rootCmd
}
