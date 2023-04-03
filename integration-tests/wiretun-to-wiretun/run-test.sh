#!/usr/bin/env bash

TUN_NAME="utun44"

export PEER1_KEY=$(wg genkey)
export PEER1_PUB=$(wg pubkey <<< ${PEER1_KEY})
export PEER2_KEY=$(wg genkey)
export PEER2_PUB=$(wg pubkey <<< ${PEER2_KEY})

echo "Peer1 key: ${PEER1_KEY}"
echo "Peer1 pubkey: ${PEER1_PUB}"
echo "Peer2 key: ${PEER2_KEY}"
echo "Peer2 pubkey: ${PEER2_PUB}"

PIDS=()

cleanup() {
  echo "Cleaning up"
  for pid in ${PIDS[@]}; do
    echo "Killing ${pid}"
    sudo kill -9 ${pid}
  done
}
trap cleanup EXIT

run_for_macos() {
  pushd peer1
  cargo build
  ./target/debug/wiretun-peer1 &> ./run.log &
  PEER1_PID=$!
  PIDS+=(${PEER1_PID})
  echo "Peer1 PID: ${PEER1_PID}"
  popd

  pushd peer2
  cargo build
  ./target/debug/wiretun-peer2 &> ./run.log &
  PEER2_PID=$!
  PIDS+=(${PEER2_PID})
  echo "Peer2 PID: ${PEER2_PID}"
  popd

  # wait for peer1 and peer2 to start
  sleep 5
  # setup route and interface
  ifconfig ${TUN_NAME} inet 10.0.0.1/32 10.0.0.1 alias
  route -q -n add -inet 10.0.0.2/32 -interface ${TUN_NAME}

  pushd tester
  cargo run
  RET=$?
  popd

  exit ${RET}
}

run() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    run_for_macos
  else
    echo "Unsupported OS"
  fi
}

run