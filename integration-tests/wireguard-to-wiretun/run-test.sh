#!/usr/bin/env bash

set -e

export PEER1_LISTEN_PORT=50081
export PEER1_KEY=oLCiGZ7J6eMjpWgBIClVGPccrnopmqIOcia8HnDN/lY=
export PEER1_PUB=jNMMQlzMwX0WeeWed9v6lINsBS3PhmF+/4fKbdfNZTA=

export PEER2_KEY=UGyzBpReHMheRGbwr5vFJ1Yu8Xkkbn5ub3F8w22y3HA=
export PEER2_PUB=KlVx32ZygXCBRK2X7ko9qF5FCVfNACzKoAglNnbt1m4=


PEER2_LOG=peer2.log
PIDS=()

cleanup() {
  echo "Cleaning up"
  for pid in ${PIDS[@]}; do
    echo "Killing ${pid}"
    sudo kill -9 ${pid}
  done
  wg-quick down ./utun.conf
}
trap cleanup EXIT

install_wireguard() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    brew install wireguard-tools
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    apt install wireguard
  else
    echo "Unsupported OS: ${OSTYPE}"
    exit 1
  fi
}

start_peer1() {
  if ! command -v wg-quick &> /dev/null
  then
    echo "wg-quick not installed, try to install it"
    install_wireguard
  fi

  cat > utun.conf <<-EOF
[Interface]
Address = 10.11.100.1/32
ListenPort = ${PEER1_LISTEN_PORT}
PrivateKey = ${PEER1_KEY}

[Peer]
PublicKey = ${PEER2_PUB}
AllowedIPs = 10.11.100.2/32
EOF

  wg-quick up ./utun.conf
}

start_peers() {
  start_peer1

  ./wiretun-peer2 &> ${PEER2_LOG} &
  PEER2_PID=$!
  PIDS+=(${PEER2_PID})
  echo "Peer2 PID: ${PEER2_PID}"
}

run() {
  start_peers
  sleep 10

  ./wiretun-tester
  RET=$?

  exit ${RET}
}

run