#!/usr/bin/env bash

set -x
set -e

# Require wireguard-tools is installed
if ! command -v wg-quick &> /dev/null
then
  echo "wg-quick not installed, please install it first"
  exit 1
fi

PIDS=()
cleanup() {
  echo "Cleaning up"
  for pid in ${PIDS[@]}; do
    echo "Killing ${pid}"
    sudo kill -9 ${pid}
  done

  # stop peer1
  wg-quick down ./utun.conf || true
  rm ./utun.conf
}
trap cleanup EXIT


# ============================================
# Start three wireguard instances:
# 1. Peer1: use `wg-quick` to setup with a native tun
# 2. Peer2: use `wiretun` to setup with stub tun
# 3. Peer3: use `wiretun` to setup with stub tun (with preshared_key)
# ============================================

PEER1_LISTEN_PORT=50081
PEER1_KEY=oLCiGZ7J6eMjpWgBIClVGPccrnopmqIOcia8HnDN/lY=
PEER1_PUB=jNMMQlzMwX0WeeWed9v6lINsBS3PhmF+/4fKbdfNZTA=

PEER2_LISTEN_PORT=50082
PEER2_NAME=peer2-stub
PEER2_KEY=UGyzBpReHMheRGbwr5vFJ1Yu8Xkkbn5ub3F8w22y3HA=
PEER2_PUB=KlVx32ZygXCBRK2X7ko9qF5FCVfNACzKoAglNnbt1m4=

PEER3_LISTEN_PORT=50083
PEER3_NAME=peer3-stub
PEER3_KEY=cHpUPuuP4kMccJFQ5KoGJih1UuSzIF6TI5rfiuRCF3U=
PEER3_PUB=h0h2J2HjfBPzLZ31UpkqvtNXYtCjWKT20xccF/B6Wgw=
PEER3_PSK=MSb1Drx0brNic2B2hAtkgKUgd4ypNbDMJZKyB4EFzlg=

rm -rf log
mkdir log
PEER2_LOG=log/peer2.log
PEER3_LOG=log/peer3.log

start_peer1() {
  cat > utun.conf <<-EOF
[Interface]
Address = 10.11.100.1/32
ListenPort = ${PEER1_LISTEN_PORT}
PrivateKey = ${PEER1_KEY}

[Peer]
PublicKey = ${PEER2_PUB}
AllowedIPs = 10.11.100.2/32

[Peer]
PublicKey = ${PEER3_PUB}
AllowedIPs = 10.11.100.3/32
PresharedKey = ${PEER3_PSK}
EOF

  wg-quick up ./utun.conf
}

start_peer2() {
  ./bin/wiretun-cli \
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
    allowed-ips 10.11.100.1/32
}

start_peer3() {
  ./bin/wiretun-cli \
    --mode stub \
    --name ${PEER3_NAME} \
    --private-key ${PEER3_KEY} \
    --listen-port ${PEER3_LISTEN_PORT} &> ${PEER3_LOG} &
  PID=$!
  PIDS+=(${PID})
  echo "Peer3 PID: ${PID}"

  sleep 5
  PEER3_PSK_FILE=$(mktemp)
  echo ${PEER3_PSK} > ${PEER3_PSK_FILE}
  wg set ${PEER3_NAME} \
    peer ${PEER1_PUB} \
    endpoint 0.0.0.0:${PEER1_LISTEN_PORT} \
    preshared-key ${PEER3_PSK_FILE} \
    allowed-ips 10.11.100.1/32
}

start_peers() {
  start_peer1
  start_peer2
  start_peer3
}

run() {
  start_peers

  ./bin/tester
  RET=$?

  exit ${RET}
}

run