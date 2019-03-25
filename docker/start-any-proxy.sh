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

NO_PROXY_LIST="127.0.0.1/8,192.168.0.1/16,172.16.0.0/12,${NO_PROXY},`ip route list | grep src | awk '{print $1}' | sed -e :a -e 'N;s/\n/,/;ta'`"
NO_PROXY_LIST=`echo ${NO_PROXY_LIST}|sed 's/,,/,/g'`

_PROXY_CONFIG=
if [ -n "${PROXY_CONFIG_FILE}" -a -e "${PROXY_CONFIG_FILE}" ]; then
  _PROXY_CONFIG="-pf ${PROXY_CONFIG_FILE}"
fi

_RANDOM=${RANDOM}
IPTABELE_OUTPUT_CHAIN=PROXY_OUTPUT_${_RANDOM}
IPTABELE_PREROUTING_CHAIN=PROXY_PREROUTING_${_RANDOM}

function install_iptables() {
  iptables -t filter -I OUTPUT 1 -p tcp -m mark --mark ${IPTABLE_MARK} --dport ${LISTEN_PORT} -j REJECT

  iptables -t nat -N ${IPTABELE_OUTPUT_CHAIN}
  iptables -t nat -A ${IPTABELE_OUTPUT_CHAIN} -p tcp -j RETURN -d ${NO_PROXY_LIST}
  iptables -t nat -A ${IPTABELE_OUTPUT_CHAIN} -p tcp -j REDIRECT --to-port ${LISTEN_PORT}
  iptables -t nat -A OUTPUT -p tcp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${PROXY_PORTS} -j ${IPTABELE_OUTPUT_CHAIN}

  iptables -t nat -N ${IPTABELE_PREROUTING_CHAIN}
  iptables -t nat -A ${IPTABELE_PREROUTING_CHAIN} -p tcp -j RETURN -d ${NO_PROXY_LIST}
  iptables -t nat -A ${IPTABELE_PREROUTING_CHAIN} -p tcp -j MARK --set-mark ${IPTABLE_MARK}
  iptables -t nat -A ${IPTABELE_PREROUTING_CHAIN} -p tcp -j REDIRECT --to-port ${LISTEN_PORT}
  iptables -t nat -A PREROUTING -p tcp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${PROXY_PORTS} -j ${IPTABELE_PREROUTING_CHAIN}

  iptables -t filter -I INPUT 1 -p tcp -m mark --mark ${IPTABLE_MARK} --dport ${LISTEN_PORT} -m conntrack --ctstate NEW -j ACCEPT

  if [ "${DNS_PORT}" -gt 0 ]; then
    iptables -t nat -A OUTPUT -p udp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${DNS_PORT} -j REDIRECT --to-port ${LISTEN_PORT}
    iptables -t nat -A PREROUTING -p udp -m multiport --dports ${DNS_PORT} -j REDIRECT --to-port ${LISTEN_PORT}
  fi
  IPTABLE_SET=1
}

function uninstall_iptables() {
  if [ "${IPTABLE_SET}" == 0 ]; then
    return
  fi
  trap - 0 2 3 15
  iptables -t filter -D OUTPUT -p tcp -m mark --mark ${IPTABLE_MARK} --dport ${LISTEN_PORT} -j REJECT

  iptables -t nat -D OUTPUT -p tcp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${PROXY_PORTS} -j ${IPTABELE_OUTPUT_CHAIN}
  iptables -t nat -F ${IPTABELE_OUTPUT_CHAIN}
  iptables -t nat -X ${IPTABELE_OUTPUT_CHAIN}

  iptables -t nat -D PREROUTING -p tcp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${PROXY_PORTS} -j ${IPTABELE_PREROUTING_CHAIN}
  iptables -t nat -F ${IPTABELE_PREROUTING_CHAIN}
  iptables -t nat -X ${IPTABELE_PREROUTING_CHAIN}

  iptables -t filter -D INPUT -p tcp -m mark --mark ${IPTABLE_MARK} --dport ${LISTEN_PORT} -m conntrack --ctstate NEW -j ACCEPT

  if [ "${DNS_PORT}" -gt 0 ]; then
    iptables -t nat -D OUTPUT -p udp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${DNS_PORT} -j REDIRECT --to-port ${LISTEN_PORT}
    iptables -t nat -D PREROUTING -p udp -m multiport --dports ${DNS_PORT} -j REDIRECT --to-port ${LISTEN_PORT}
  fi
  IPTABLE_SET=0
}

_DNS_LISTEN_PORT=
if [ "${DNS_PORT}" -gt 0 ];  then
  _DNS_LISTEN_PORT="-dns :${LISTEN_PORT}"
fi

trap 'uninstall_iptables; kill -TERM ${PID}' 0 2 3 15

/bin/go-any-proxy -l :${LISTEN_PORT} -p ${HTTP_PROXY} -d ${NO_PROXY_LIST} -v=${PROXY_VERBOSE} -f=/dev/stdout -k ${IPTABLE_MARK} ${_DNS_LISTEN_PORT} ${_PROXY_CONFIG}&

PID=$!

install_iptables

wait $PID

uninstall_iptables

wait $PID
