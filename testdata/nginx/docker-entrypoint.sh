#!/bin/bash
apt-get update
apt-get install iproute2 dnsutils iputils-ping -y

HOST_DOMAIN="host.docker.internal"
ping -q -c1 $HOST_DOMAIN > /dev/null 2>&1
if [ $? -ne 0 ]; then
  # HOST_IP=$(ip route | awk '/default/ { print $3 }' | awk '!seen[$0]++')
  HOST_IP=127.0.0.1
  echo -e "$HOST_IP\t$HOST_DOMAIN" >> /etc/hosts
  cat /etc/hosts
fi
exec nginx -g 'daemon off;'
