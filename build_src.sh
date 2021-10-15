#!/usr/bin/env bash

echo "MAJ common"
git submodule update --recursive

echo "Build target rust"
cargo b --release --package millegrilles_senseurspassifs --bin millegrilles_senseurspassifs


