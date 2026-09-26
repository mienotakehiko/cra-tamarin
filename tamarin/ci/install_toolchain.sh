#!/usr/bin/env bash
# Install the exact toolchain used for the paper's Table 3 into $PREFIX/bin
# (default ./.toolchain).  Linux x86_64 only.  CI and local installs both use it.
#   tamarin-prover 1.12.0 (official release binary)
#   maude 3.5.1           (supported by Tamarin 1.12.0; results are identical
#                          to maude 3.2, which Tamarin 1.12.0 flags as
#                          'unsupported')
set -euo pipefail
PREFIX=${PREFIX:-$(pwd)/.toolchain}
TAMARIN_VER=1.12.0
MAUDE_VER=3.5.1
mkdir -p "$PREFIX/bin" "$PREFIX/src"
cd "$PREFIX/src"
curl -fsSL -o tamarin.tgz \
  "https://github.com/tamarin-prover/tamarin-prover/releases/download/${TAMARIN_VER}/tamarin-prover-${TAMARIN_VER}-linux64-ubuntu.tar.gz"
tar xzf tamarin.tgz
install -m 755 tamarin-prover "$PREFIX/bin/tamarin-prover"
curl -fsSL -o maude.zip \
  "https://github.com/maude-lang/Maude/releases/download/Maude${MAUDE_VER}/Maude-${MAUDE_VER}-linux-x86_64.zip"
rm -rf maude && mkdir maude && (cd maude && unzip -q ../maude.zip)
MBIN=$(find maude -type f -name 'maude*' -perm -u+x | grep -v '\.maude$' | head -1)
install -m 755 "$MBIN" "$PREFIX/bin/maude"
cp maude/*.maude "$PREFIX/bin/"          # prelude.maude etc. next to the binary
echo "export PATH=$PREFIX/bin:\$PATH"
"$PREFIX/bin/maude" --version
"$PREFIX/bin/tamarin-prover" --version 2>&1 | head -1
