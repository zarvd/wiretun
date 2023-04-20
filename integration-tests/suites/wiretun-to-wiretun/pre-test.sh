#!/usr/bin/env bash

set -e

pushd peer1
cargo build
popd

pushd peer2
cargo build
popd

pushd tester
cargo build
popd

rm -rf ./bin
mkdir ./bin
cp peer1/target/debug/wiretun-to-wiretun-peer1 bin/peer1
cp peer2/target/debug/wiretun-to-wiretun-peer2 bin/peer2
cp tester/target/debug/wiretun-to-wiretun-tester bin/tester