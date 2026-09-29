# gittuf-setup.ps1
# Working end-to-end setup script for gittuf PoC (local-only, no remote required)
# Tested on Windows with PowerShell + Git for Windows + gittuf
#
# Usage (run from repo root):
#   PowerShell -ExecutionPolicy Bypass -File gittuf-setup.ps1
#
# Prereqs:
#   - gittuf in PATH  (go install github.com/gittuf/gittuf@latest)
#   - OpenSSH (ssh-keygen) in PATH

$ErrorActionPreference = "Stop"

$RepoDir = "poc-repo"
$KeysDir = ".."   # keys generated one level up so they stay out of the repo

Write-Host "==> [1/5] Generating SSH keys" -ForegroundColor Cyan
ssh-keygen -t ed25519 -f "$KeysDir/root" -N '""'
ssh-keygen -t ed25519 -f "$KeysDir/dev"  -N '""'

Write-Host "==> [2/5] Creating Git repository" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $RepoDir -Force | Out-Null
Set-Location $RepoDir

git init -b main
git config user.name  "Aastha"
git config user.email "aastha@example.com"

# IMPORTANT: tell git to use SSH for commit signing, NOT GPG.
# Without this, gittuf trust init fails with "gpg: No secret key".
git config gpg.format      ssh
git config user.signingkey "$KeysDir/root.pub"

"v1" | Out-File -Encoding utf8 file.txt
git add file.txt; git commit -m "c1"

"v2" | Out-File -Append -Encoding utf8 file.txt
git add file.txt; git commit -m "c2"

Write-Host "==> [3/5] Initialising gittuf trust + policy" -ForegroundColor Cyan
#
# KEY INSIGHT: every mutating trust/policy command must carry --create-rsl-entry
# so the RSL stays in sync with the policy ref.  If you skip it, `policy apply`
# throws: "invalid policy state (is policy reference out of sync with RSL?)"
#
# Also: --authorize in add-rule takes a PERSON-ID, not a key fingerprint.
# You must call `policy add-person` first to register the key under an ID.

gittuf trust init `
    -k "$KeysDir/root" `
    --create-rsl-entry

gittuf trust add-policy-key `
    --policy-key "$KeysDir/root.pub" `
    -k "$KeysDir/root" `
    --create-rsl-entry

gittuf policy init `
    -k "$KeysDir/root" `
    --create-rsl-entry

gittuf policy add-person `
    --person-ID  dev `
    --public-key "$KeysDir/dev.pub" `
    -k "$KeysDir/root" `
    --create-rsl-entry

gittuf policy add-rule `
    --rule-name    protect-main `
    --rule-pattern refs/heads/main `
    --authorize    dev `
    -k "$KeysDir/root" `
    --create-rsl-entry

# apply: moves staging -> policy and writes its own RSL entry automatically
gittuf policy apply --local-only -k "$KeysDir/root"

Write-Host "==> [4/5] Recording RSL entries and making commit c3" -ForegroundColor Cyan
gittuf rsl record --local-only main        # record state before new work

"v3" | Out-File -Append -Encoding utf8 file.txt
git add file.txt; git commit -m "c3"

gittuf rsl record --local-only main        # record state after new work

Write-Host "==> [5/5] Verifying ref" -ForegroundColor Cyan
gittuf verify-ref --verbose main
if ($LASTEXITCODE -eq 0) {
    Write-Host "`nVerification PASSED -- EXIT 0" -ForegroundColor Green
} else {
    Write-Host "`nVerification FAILED -- EXIT $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
