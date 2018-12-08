#!/bin/sh

PROXY_VERBOSE=0

if [[ "${VERBOSE}" != false ]]; then
  PROXY_VERBOSE=1
  set -x
fi

if [[ -z "${HTTP_PROXY}" ]]; then
  echo Need upstream proxy set on environment variable HTTP_PROXY 1>&2
  exit 1
fi

NO_PROXY_LIST="127.0.0.1/8,192.168.0.1/16,10.0.0.1/8,172.16.0.0/12,${NO_PROXY},`ip route list | grep src | awk '{print $1}' | sed -e :a -e 'N;s/\n/,/;ta'`"
NO_PROXY_LIST=`echo ${NO_PROXY_LIST}|sed 's/,,/,/g'`

_PROXY_CONFIG=
if [[ -n "${PROXY_CONFIG_FILE}" && -e "${PROXY_CONFIG_FILE}" ]]; then
  _PROXY_CONFIG="-pf ${PROXY_CONFIG_FILE}"
fi

_DNS_LISTEN_PORT=
if [[ "${DNS_PORT}" -gt 0 ]];  then
  _DNS_LISTEN_PORT="-dns :${LISTEN_PORT}"
fi

exec /bin/go-any-proxy -l :${LISTEN_PORT} -ports ${PROXY_PORTS} -p ${HTTP_PROXY} -d ${NO_PROXY_LIST} -v=${PROXY_VERBOSE} -f=/dev/stdout -k ${IPTABLE_MARK} ${_DNS_LISTEN_PORT} ${_PROXY_CONFIG}