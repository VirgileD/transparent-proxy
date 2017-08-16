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
  iptables -t nat -A OUTPUT -o e+ -p tcp --match multiport --dports ${PROXY_PORTS} -j ACCEPT -d ${NO_PROXY_LIST}
  iptables -t nat -A OUTPUT -o e+ -p tcp --match multiport --dports ${PROXY_PORTS} -j REDIRECT --to-port ${LISTEN_PORT}
  iptables -t nat -A PREROUTING -i docker+ -p tcp --match multiport --dports ${PROXY_PORTS} -j ACCEPT -d ${NO_PROXY_LIST}
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
  iptables -t filter -D OUTPUT -p tcp -m mark --mark ${IPTABLE_MARK} --dport ${LISTEN_PORT} -j REJECT
  iptables -t nat -D OUTPUT -p tcp -m mark --mark ${IPTABLE_MARK} -j ACCEPT
  iptables -t nat -D OUTPUT -o e+ -p tcp --match multiport --dports ${PROXY_PORTS} -j ACCEPT -d ${NO_PROXY_LIST}
  iptables -t nat -D OUTPUT -o e+ -p tcp --match multiport --dports ${PROXY_PORTS} -j REDIRECT --to-port ${LISTEN_PORT}
  iptables -t nat -D PREROUTING -i docker+ -p tcp --match multiport --dports ${PROXY_PORTS} -j ACCEPT -d ${NO_PROXY_LIST}
  iptables -t nat -D PREROUTING -i docker+ -p tcp --match multiport --dports ${PROXY_PORTS} -j REDIRECT --to-port ${LISTEN_PORT}
  IPTABLE_SET=0
}

install_iptables

/bin/go-any-proxy -l :${LISTEN_PORT} -p ${HTTP_PROXY} -d ${NO_PROXY_LIST} -v=${PROXY_VERBOSE} -f=/dev/stdout -k ${IPTABLE_MARK} &

PID=$!
wait $PID

uninstall_iptables
