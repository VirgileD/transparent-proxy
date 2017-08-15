**This is fork project from https://github.com/ryanchapman/go-any-proxy, but add a few features.**
# Any Proxy

go-any-proxy is a server that can transparently proxy any tcp connection through an upstream proxy server.  This type
of setup is common in corporate environments.  It is written in golang and has been load tested with 10,000 concurrent
connections successfully on a Vyatta running a 64-bit kernel.

## More info

For more info, see http://blog.rchapman.org/post/47406142744/transparently-proxying-http-and-https-connections

## Authentication

You can add basic authentication parameters if needed, like this:

`any_proxy -l :3140 -p "MyLogin:Password25@proxy.corporate.com:8080"`

## Install Info 
You may need to run `go get` for library dependencies.

## Docker Integration (**New**)
This project support docker and integrated iptables for container start/stop.

Using following command to start transparent proxy on host:
```
docker run -it --rm --privileged -e HTTP_PROXY=proxy.corporate.com:8080 -e NO_PROXY=192.176.0.1/8,172.10.0.1/8 -e LISTEN_PORT=3129 -e IPTABLE_MARK=2515 -e PROXY_PORTS=80,443,22 --net=host feng-zh/transparent-proxy
```

The options are important for run docker:
* "--privileged": This option is required for application to set socket options for SO_MARK.
* "--net=host": This option is required to setup iptables inside of container, and get original ip/port when get connection redirected from iptables.
* Env "HTTP_PROXY": This is upstream proxy, should support "CONNECT" HTTP method (Usually it is http proxy for HTTPS).
* Env "NO_PROXY": This is optional value to by pass network address without go through upstream proxy.
* Env "LISTEN_PORT": This is optional value and it can be any open port. Default value is "3129".
* Env "IPTABLE_MASK": This is optional value, and should be different with other mark value used in iptables. Default value is "5".
* Env "PROXY_PORTS": This is optional value for ports that can be transparent to proxy. The default value is "80,443".
