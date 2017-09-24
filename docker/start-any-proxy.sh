#!/bin/sh

PROXY_VERBOSE=0

if [ "${VERBOSE}" != false ]; then
  PROXY_VERBOSE=1
  set -x
fi

if [ -z "${HTTP_PROXY}" ]; then
  echo Need upstream proxy set on environment variable HTTP_PROXY 1>&2
  exit 1
fi

IPTABLE_SET=1

NO_PROXY_LIST="127.0.0.1/8,192.168.0.1/16,10.0.0.1/8,${NO_PROXY},`ip route list | grep src | awk '{print $1}' | sed -e :a -e 'N;s/\n/,/;ta'`"

function install_iptables() {
  iptables -t filter -I OUTPUT 1 -p tcp -m mark --mark ${IPTABLE_MARK} --dport ${LISTEN_PORT} -j REJECT
  iptables -t nat -I OUTPUT 1 -p tcp -m mark --mark ${IPTABLE_MARK} -j ACCEPT
  iptables -t nat -A OUTPUT -p tcp --match multiport --dports ${PROXY_PORTS} -j ACCEPT -d ${NO_PROXY_LIST}
  iptables -t nat -A OUTPUT -p tcp --match multiport --dports ${PROXY_PORTS} -j REDIRECT --to-port ${LISTEN_PORT}
  iptables -t nat -A PREROUTING -p tcp --match multiport --dports ${PROXY_PORTS} -j ACCEPT -d ${NO_PROXY_LIST}
  iptables -t nat -A PREROUTING -p tcp --match multiport --dports ${PROXY_PORTS} -j REDIRECT --to-port ${LISTEN_PORT}
  IPTABLE_SET=1
}

function uninstall_iptables() {
  if [ "${IPTABLE_SET}" == 0 ]; then
    return
  fi
  trap - 0 2 3 15
  iptables -t filter -D OUTPUT -p tcp -m mark --mark ${IPTABLE_MARK} --dport ${LISTEN_PORT} -j REJECT
  iptables -t nat -D OUTPUT -p tcp -m mark --mark ${IPTABLE_MARK} -j ACCEPT
  iptables -t nat -D OUTPUT -p tcp --match multiport --dports ${PROXY_PORTS} -j ACCEPT -d ${NO_PROXY_LIST}
  iptables -t nat -D OUTPUT -p tcp --match multiport --dports ${PROXY_PORTS} -j REDIRECT --to-port ${LISTEN_PORT}
  iptables -t nat -D PREROUTING -p tcp --match multiport --dports ${PROXY_PORTS} -j ACCEPT -d ${NO_PROXY_LIST}
  iptables -t nat -D PREROUTING -p tcp --match multiport --dports ${PROXY_PORTS} -j REDIRECT --to-port ${LISTEN_PORT}
  IPTABLE_SET=0
}

trap 'uninstall_iptables; kill -TERM $PID' 0 2 3 15

/bin/go-any-proxy -l :${LISTEN_PORT} -p ${HTTP_PROXY} -d ${NO_PROXY_LIST} -v=${PROXY_VERBOSE} -f=/dev/stdout -k ${IPTABLE_MARK} &

PID=$!

install_iptables

wait $PID

uninstall_iptables

wait $PID
