#!/bin/sh

PROXY_DEBUG=0

if [ "${DEBUG}" != false ]; then
  PROXY_DEBUG=1
  set -x
fi

if [ -z "${HTTP_PROXY}" ]; then
  echo Need upstream proxy set on environment variable HTTP_PROXY 1>&2
  exit 1
fi

IPTABLE_SET=1

function install_iptables() {
  iptables -t nat -I OUTPUT 1 -p tcp -m mark --mark ${IPTABLE_MARK} -j ACCEPT
  iptables -t nat -A OUTPUT -o e+ -p tcp ! -d 127.0.0.1/8 --match multiport --dports ${PROXY_PORTS} -j REDIRECT --to-port ${LISTEN_PORT}
  iptables -t nat -A PREROUTING -i docker+ -p tcp --match multiport --dports ${PROXY_PORTS} -j REDIRECT --to-port ${LISTEN_PORT}
  trap 'kill -TERM $PID; uninstall_iptables' 0 2 3 15
  IPTABLE_SET=1
}

function uninstall_iptables() {
  if [ "${IPTABLE_SET}" == 0 ]; then
    return
  fi
  trap - 0 2 3 15
  wait $PID
  iptables -t nat -D OUTPUT -p tcp -m mark --mark ${IPTABLE_MARK} -j ACCEPT
  iptables -t nat -D OUTPUT -o e+ -p tcp ! -d 127.0.0.1/8 --match multiport --dports ${PROXY_PORTS} -j REDIRECT --to-port ${LISTEN_PORT}
  iptables -t nat -D PREROUTING -i docker+ -p tcp --match multiport --dports ${PROXY_PORTS} -j REDIRECT --to-port ${LISTEN_PORT}
  IPTABLE_SET=0
}

install_iptables

/bin/go-any-proxy -l :${LISTEN_PORT} -p ${HTTP_PROXY} -d "127.0.0.1/8,192.168.0.1/16,10.0.0.1/8,${NO_PROXY},`ip route list | grep src | awk '{print $1}' | sed -e :a -e 'N;s/\n/,/;ta'`" -v=${PROXY_DEBUG} -f=/dev/stdout -k ${IPTABLE_MARK} &

PID=$!
wait $PID

uninstall_iptables
