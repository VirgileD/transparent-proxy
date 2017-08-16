FROM alpine

COPY . /src

RUN /src/docker/docker-build.sh

ENV LISTEN_PORT=3129 HTTP_PROXY="" NO_PROXY="127.0.0.1/8" IPTABLE_MARK="5" PROXY_PORTS="80,443" VERBOSE=false

CMD ["/bin/start-any-proxy.sh"]
