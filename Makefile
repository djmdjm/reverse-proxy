INSTALL="install -o root -g wheel"

all: reverse-proxy

reverse-proxy: reverse-proxy.go
	go build

clean:
	rm reverse-proxy

install:
	$(INSTALL) -d -m 0755 /usr/local/sbin
	$(INSTALL) -m 0755 reverse-proxy /usr/local/sbin
	$(INSTALL) -m 0555 reverse_proxy.rc /etc/rc.d/reverse_proxy
	test -f /etc/reverse-proxy.json || \
		$(INSTALL) -m 0644 reverse-proxy.json /etc

