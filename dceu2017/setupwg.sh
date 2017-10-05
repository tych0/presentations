#!/bin/bash

set -e
set -x

if [ -z "$1" ]; then
    echo "gimmie an argument"
    exit 1
fi

IP=192.168.3.$1
NAME=container$1
PID=$(docker inspect $NAME | jq .[0].State.Pid)

mkdir -p /var/run/netns
touch /var/run/netns/$NAME
mount --bind /proc/$PID/ns/net /var/run/netns/$NAME

ip link add wg0 type wireguard
ip link set wg0 netns $NAME
ip -n $NAME addr add 192.168.3.$1 dev wg0
ip netns exec $NAME /home/ubuntu/WireGuard/src/tools/wg setconf wg0 /home/ubuntu/presentations/dceu2017/$NAME.wgconf
ip -n $NAME link set wg0 up
ip -n $NAME route add default dev wg0
umount /var/run/netns/$NAME
