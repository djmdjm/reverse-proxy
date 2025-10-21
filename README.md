# Simple reverse proxy

This is a simple privilege-dropping, HTTPS/HTTP to HTTP reverse proxy.

It supports multiple listeners with independant TLS keys/certificates that
each relay to a single HTTP backend. It can optionally override response
headers returned by the backend.

The configuration is via JSON. Note that the proxy will only relay
requests with a name that appears in the `AllowHost` configuration
field. This naturally precludes it from being used for HTTP/1.0 services,
sorry.

The proxy runs in the foreground and logs to syslog, SIGINT or SIGTERM
will gracefully terminate it. If it is started with root privileges, then
after TLS keys have been loaded and listeners have started it will drop
privileges to the `PrivdropUser` specified in the config file.

It's written in Go, and can be built using `go build` after checkout.
It uses no dependencies outside the Go standard library, so it should
be very easy to get started with. Run `./reverse-proxy --help` for
information about the (few) command-line options.

There's also a Makefile, but that's mostly setup for my convenience.
E.g. it installs an OpenBSD rc.d init script. You might want to ignore
that.

This was written in a few hours for my specific needs, but a few people
asked about it so I've made it public.

