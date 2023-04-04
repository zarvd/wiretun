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

cp peer1/target/debug/wiretun-peer1 wiretun-peer1
cp peer2/target/debug/wiretun-peer2 wiretun-peer2
cp tester/target/debug/wiretun-tester wiretun-tester