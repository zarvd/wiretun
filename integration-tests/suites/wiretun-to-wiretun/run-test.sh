#!/usr/bin/env bash

set -e

TUN_NAME="utun44"

export PEER1_KEY=oLCiGZ7J6eMjpWgBIClVGPccrnopmqIOcia8HnDN/lY=
export PEER1_PUB=jNMMQlzMwX0WeeWed9v6lINsBS3PhmF+/4fKbdfNZTA=
export PEER2_KEY=UGyzBpReHMheRGbwr5vFJ1Yu8Xkkbn5ub3F8w22y3HA=
export PEER2_PUB=KlVx32ZygXCBRK2X7ko9qF5FCVfNACzKoAglNnbt1m4=

PEER1_LOG=peer1.log
PEER2_LOG=peer2.log

PIDS=()

cleanup() {
  echo "Cleaning up"
  for pid in ${PIDS[@]}; do
    echo "Killing ${pid}"
    sudo kill -9 ${pid}
  done
}
trap cleanup EXIT

start_peers() {
  ./bin/peer1 &> ${PEER1_LOG} &
  PEER1_PID=$!
  PIDS+=(${PEER1_PID})
  echo "Peer1 PID: ${PEER1_PID}"

  ./bin/peer2 &> ${PEER2_LOG} &
  PEER2_PID=$!
  PIDS+=(${PEER2_PID})
  echo "Peer2 PID: ${PEER2_PID}"
}

run_for_macos() {
  start_peers
  # wait for peer1 and peer2 to start
  sleep 10
  # setup route and interface
  ifconfig ${TUN_NAME} inet 10.0.0.1/32 10.0.0.1 alias
  route -q -n add -inet 10.0.0.2/32 -interface ${TUN_NAME}

  ./bin/tester
  RET=$?

  exit ${RET}
}

run_for_linux() {
  start_peers
  # wait for peer1 and peer2 to start
  sleep 10
  # setup route and interface
  ip -4 address add 10.0.0.1/32 dev ${TUN_NAME}
  ip link set mtu 1420 up dev ${TUN_NAME}
  ip -4 route add 10.0.0.2/32 dev ${TUN_NAME}

  ./bin/tester
  RET=$?

  exit ${RET}
}

run() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    run_for_macos
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    run_for_linux
  else
    echo "Unsupported OS: ${OSTYPE}"
    exit 1
  fi
}

run