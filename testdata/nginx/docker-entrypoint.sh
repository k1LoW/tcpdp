#!/bin/bash
apt-get update
apt-get install iproute2 -y

HOST_DOMAIN="host.docker.internal"
ping -q -c1 $HOST_DOMAIN > /dev/null 2>&1
if [ $? -ne 0 ]; then
  ip route
  HOST_IP=$(ip route | awk 'NR==1 {print $3}')
  echo "$HOST_IP"
  echo -e "$HOST_IP\t$HOST_DOMAIN" >> /etc/hosts
  cat /etc/hosts
fi
exec nginx -g 'daemon off;'
