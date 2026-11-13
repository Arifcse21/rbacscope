# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through **GitHub → Security → Report a vulnerability** (private security advisory). Do not open a public issue. You should get an acknowledgement within 3 working days. Fixes ship as a patch release with a published advisory.

Only the latest minor release is supported with security fixes.

## What rbacscope can see

- **CLI (`--live`, `dump`) and exporter (`serve`)** use read-only `list` calls on Roles, RoleBindings, ClusterRoles, ClusterRoleBindings, ServiceAccounts and (optionally) Pods. They never read Secrets.
- From Pods, only namespace, ServiceAccount, token-automount setting and phase are kept. Environment variables and other spec fields are dropped before anything is stored, printed or served.
- Audit logs (`generate`, `unused`) are read locally and never sent anywhere.
- The **report and metrics describe your cluster's weak spots**. The Helm chart ships a ClusterIP Service and a NetworkPolicy that admits only the `monitoring` namespace; keep it that way.

## Verifying releases

Every artifact is signed keylessly with [Sigstore](https://www.sigstore.dev/) from the GitHub Actions release workflow, and has SLSA build provenance. Replace the version below.

```sh
VERSION=v0.6.0
IDENTITY='^https://github.com/Arifcse21/rbacscope/\.github/workflows/release\.yml@refs/tags/v.*$'
ISSUER=https://token.actions.githubusercontent.com

# 1. Binaries: verify the signed checksum file, then the archive against it
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
sha256sum --check --ignore-missing SHA256SUMS

# 2. Build provenance (which workflow, commit and runner produced the file)
gh attestation verify rbacscope-$VERSION-x86_64-unknown-linux-musl.tar.gz --repo Arifcse21/rbacscope

# 3. Container image
cosign verify ghcr.io/arifcse21/rbacscope:${VERSION#v} \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
gh attestation verify oci://ghcr.io/arifcse21/rbacscope:${VERSION#v} --repo Arifcse21/rbacscope

# 4. Helm chart (the packaged chart pins the image by digest)
cosign verify ghcr.io/arifcse21/charts/rbacscope:${VERSION#v} \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

Each release also attaches an SPDX SBOM (`rbacscope-<version>.spdx.json`); the image carries its own SBOM and provenance attestations (`docker buildx imagetools inspect --format '{{json .SBOM}}' ghcr.io/arifcse21/rbacscope:<version>`).
