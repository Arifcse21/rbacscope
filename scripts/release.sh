#!/usr/bin/env bash
# Prepare a release: set the version everywhere, commit, and create the tag.
# Pushing the tag runs .github/workflows/release.yml, which publishes the signed
# image and Helm chart to ghcr.io.
#
#   scripts/release.sh 0.6.1
#   git push origin main && git push origin v0.6.1
set -euo pipefail

new="${1:-}"
if [[ ! "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: scripts/release.sh X.Y.Z" >&2
  exit 1
fi
cd "$(git rev-parse --show-toplevel)"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: commit or stash your changes first" >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/v$new" >/dev/null; then
  echo "error: tag v$new already exists" >&2
  exit 1
fi

old="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"

if [ "$old" != "$new" ]; then
  echo "Bumping $old -> $new"
  # Workspace version and the internal crate dependency versions.
  sed -i "s/^version = \"$old\"/version = \"$new\"/; s/version = \"$old\" }/version = \"$new\" }/g" Cargo.toml
  sed -i "s/^version: $old\$/version: $new/; s/^appVersion: \"$old\"\$/appVersion: \"$new\"/" charts/rbacscope/Chart.yaml
  sed -i "s|ghcr.io/arifcse21/rbacscope:$old|ghcr.io/arifcse21/rbacscope:$new|" deploy/kubernetes/rbacscope.yaml
  sed -i "s|Arifcse21/rbacscope@v$old|Arifcse21/rbacscope@v$new|g" README.md
  sed -i "s|^VERSION=v$old\$|VERSION=v$new|" SECURITY.md

  # Refresh Cargo.lock (CI builds with --locked). Use the Rust container if cargo isn't installed.
  if command -v cargo >/dev/null; then
    cargo update --workspace --quiet
  else
    docker run --rm -u "$(id -u):$(id -g)" -e CARGO_HOME=/tmp/cargo -v "$PWD:/src" -w /src rust:1-slim \
      cargo update --workspace --quiet
  fi

  git add Cargo.toml Cargo.lock charts/rbacscope/Chart.yaml deploy/kubernetes/rbacscope.yaml README.md SECURITY.md
  git commit -q -m "Release v$new"
else
  echo "Version is already $new; tagging the current commit"
fi

# The release workflow refuses tags that don't match these.
grep -q "^version = \"$new\"" Cargo.toml
grep -q "^version: $new\$" charts/rbacscope/Chart.yaml
grep -q "^appVersion: \"$new\"\$" charts/rbacscope/Chart.yaml

git tag -a "v$new" -m "rbacscope v$new"
echo
echo "Tagged v$new. Publish it with:"
echo "  git push origin main && git push origin v$new"
