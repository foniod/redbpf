#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $SCRIPT_DIR/..

PACKAGES="bpf-sys redbpf redbpf-probes redbpf-macros cargo-bpf"

NEW_VERSION="${1}"

echo "Bumping version: ${NEW_VERSION}"

find $PACKAGES -name Cargo.toml -type f -exec sed -i -e "s/^version.*/version = \"$NEW_VERSION\"/" {} \;
find $PACKAGES -name Cargo.toml -type f -exec sed -i -e "s/^\(bpf-sys.*version = \)\"[^\"]*\"/\\1\"$NEW_VERSION\"/" {} \;
find $PACKAGES -name Cargo.toml -type f -exec sed -i -e "s/^\(cargo-bpf.*version = \)\"[^\"]*\"/\\1\"$NEW_VERSION\"/" {} \;
find $PACKAGES -name Cargo.toml -type f -exec sed -i -e "s/^\(redbpf.*version = \)\"[^\"]*\"/\\1\"$NEW_VERSION\"/" {} \;
