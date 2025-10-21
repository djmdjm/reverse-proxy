all: reverse-proxy

reverse-proxy: reverse-proxy.go
	go build

clean:
	rm reverse-proxy

install:
	install -d -o root -g wheel /usr/local/sbin
	install -o root -g wheel -m 0755 reverse-proxy /usr/local/sbin
	install -o root -g wheel -m 0555 reverse_proxy.rc /etc/rc.d/reverse_proxy
	test -f /etc/reverse-proxy.json || \
		install -o root -g wheel -m 0644 reverse-proxy.json /etc

