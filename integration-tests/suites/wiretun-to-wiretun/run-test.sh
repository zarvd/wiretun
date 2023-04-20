#!/usr/bin/env bash

set -x
set -e

PIDS=()
cleanup() {
  echo "Cleaning up"
  for pid in ${PIDS[@]}; do
    echo "Killing ${pid}"
    sudo kill -9 ${pid}
  done
}
trap cleanup EXIT

PEER1_LISTEN_PORT=50081
PEER1_NAME=utun44
PEER1_KEY=oLCiGZ7J6eMjpWgBIClVGPccrnopmqIOcia8HnDN/lY=
PEER1_PUB=jNMMQlzMwX0WeeWed9v6lINsBS3PhmF+/4fKbdfNZTA=
PEER1_ADDR=10.11.101.1/32

PEER2_LISTEN_PORT=50082
PEER2_NAME=peer2-stub
PEER2_KEY=UGyzBpReHMheRGbwr5vFJ1Yu8Xkkbn5ub3F8w22y3HA=
PEER2_PUB=KlVx32ZygXCBRK2X7ko9qF5FCVfNACzKoAglNnbt1m4=
PEER2_ADDR=10.11.101.2/32

rm -rf log
mkdir log
PEER1_LOG=log/peer1.log
PEER2_LOG=log/peer2.log

start_peer1() {
  ./bin/wiretun-cli \
    --mode native \
    --name ${PEER1_NAME} \
    --private-key ${PEER1_KEY} \
    --listen-port ${PEER1_LISTEN_PORT} &> ${PEER1_LOG} &
  PID=$!
  PIDS+=(${PID})
  echo "Peer1 PID: ${PID}"

  sleep 5
  wg set ${PEER1_NAME} \
    peer ${PEER2_PUB} \
    endpoint 0.0.0.0:${PEER2_LISTEN_PORT} \
    allowed-ips ${PEER2_ADDR}

  if [[ "$OSTYPE" == "darwin"* ]]; then
    ifconfig ${PEER1_NAME} inet ${PEER1_ADDR} 10.11.101.1 alias
    route -q -n add -inet ${PEER2_ADDR} -interface ${PEER1_NAME}
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    ip -4 address add ${PEER1_ADDR} dev ${PEER1_NAME}
    ip link set mtu 1420 up dev ${PEER1_NAME}
    ip -4 route add ${PEER2_ADDR} dev ${PEER1_NAME}
  else
    echo "Unsupported OS: ${OSTYPE}"
    exit 1
  fi
}

start_peer2() {
  RUST_BACKTRACE=1 ./bin/wiretun-cli \
    --mode stub \
    --name ${PEER2_NAME} \
    --private-key ${PEER2_KEY} \
    --listen-port ${PEER2_LISTEN_PORT} &> ${PEER2_LOG} &
  PID=$!
  PIDS+=(${PID})
  echo "Peer2 PID: ${PID}"

  sleep 5
  wg set ${PEER2_NAME} \
    peer ${PEER1_PUB} \
    endpoint 0.0.0.0:${PEER1_LISTEN_PORT} \
    allowed-ips ${PEER1_ADDR}
}

start_peers() {
  start_peer1
  start_peer2
}

run() {
  start_peers
  sleep 10
  ./bin/tester
  RET=$?
  exit ${RET}
}

run