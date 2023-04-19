#!/usr/bin/env bash

set -e


pushd peer2
cargo build
popd

pushd tester
cargo build
popd

cp peer2/target/debug/wiretun-peer2 wiretun-peer2
cp tester/target/debug/wiretun-tester wiretun-tester
