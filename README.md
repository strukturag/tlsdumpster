TLS dumpster
=============

TLS dumpster prints incoming TLS requests details (host, url, headers and body) to stdout and aborts the request with HTTP status 500.

## Build prerequisites

  - [Go](http://golang.org) >= 1.1.0

## Building

  Setup up your gopath

    $ mkdir -p $HOME/go
    $ export GOPATH=$HOME/go

  For convenience, add the workspace's bin subdirectory to your PATH

  	$ export PATH=$PATH:$GOPATH/bin

  Get and build TLS dumpster

    $ go get github.com/strukturag/tlsdumpster
    $ tlsdumpster -h
    Usage of tlsdumpster:
      -cert="": Certificate file.
      -key="": Key file.
      -l="127.0.0.1:8443": Listen address.

## Usage

  Intercept traffic

  	sudo iptables -t nat -A OUTPUT -p tcp --dst $TARGET --dport 443 -j DNAT --to-destination 127.0.0.1:8443

  Where $TARGET is the IP address of the target. Make sure that the desitination IP and port match whatever you start tlsdumpster with.

  Start tlsdumpster

	$ tlsdumpster -l=127.0.0.1:8443 -cert=cert.pem -key=key.pem

  Where the cert and key are pem encoded. Make sure that the software
  does accept connecting to this certificate to see anything.

  Start your app and execute the requests. TLS dumpster will intercept all incoming requests and print them to stdout.

## License

`TLS dumpster` is using the BSD 3-clause license.