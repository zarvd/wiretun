#!/usr/bin/env bash

set -e
cargo build

cp target/debug/wiretun-native-tun ./wiretun-native-tun