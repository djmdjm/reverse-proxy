// Binary reverse-proxy is a simple reverse proxy. It listens
// using TLS or plain TCP on specified addresses/ports and
// will proxy all incoming requests to corresponding backend
// servers. Headers may be set on the way back out, e.g. to enable
// Strict-Transport-Security on plain HTTP connections.
//
// It may be started as root and will drop privileges after reading
// the TLS key material and setting up the listeners.
//
// Configuration is via a JSON blob; it's not pretty, but it avoid
// any dependencies outside the Go standard library.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"path/filepath"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var configPath = flag.String("config", "/etc/reverse-proxy.json", "Path to configuration file")
var configTest = flag.Bool("test-config", false, "Test configuration and exit")
var logToStderr = flag.Bool("logtostderr", false, "Log to stderr instead of syslog")
var configDump = flag.Bool("dump-config", false, "Test and print configuration")
var showExampleConfig = flag.Bool("example-config", false, "Print an example configuration and exit")

// ProxyConfig defines the configuration of a single proxy instance.
type ProxyConfig struct {
	Address            string
	TLS                bool
	Comment            string
	Backend            string
	TLSCert            string
	TLSKey             string
	AllowHost          []string
	ResponseSetHeaders map[string]string `json:",omitempty"`
}

// Config represents the complete user-provided configuration for this binary.
type Config struct {
	PrivdropUser string
	ProxyConfigs []ProxyConfig
}

// ProxyInstance represents the runtime state for a single proxy instance.
type ProxyInstance struct {
	ProxyConfig *ProxyConfig
	Listener    net.Listener
	Server      *http.Server
}

// State captures the runtime state for this binary.
type State struct {
	Config  *Config
	Proxies map[string]*ProxyInstance // Listen address -> server instance.
}

// exampleConfig is the example config printed via --example-config.
var exampleConfig = Config{
	ProxyConfigs: []ProxyConfig{
		ProxyConfig{
			Address:   "127.0.0.1:443",
			TLS:       true,
			Comment:   "Example HTTPS to HTTP proxy",
			Backend:   "http://127.0.0.1:8000/",
			TLSCert:   "/etc/ssl/example.com.fullchain.pem",
			TLSKey:    "/etc/ssl/private/example.com.key",
			AllowHost: []string{"example.com"},
		},
		ProxyConfig{
			Address:   "127.0.0.1:80",
			Comment:   "Example HTTP to HTTP proxy",
			Backend:   "http://127.0.0.1:8000/",
			AllowHost: []string{"example.com"},
			ResponseSetHeaders: map[string]string{
				"Strict-Transport-Security": "max-age=86400",
			},
		},
	},
	PrivdropUser: "reverse-proxy",
}

// loadConfiguration loads and parses a JSON configuration from the
// specified path.
func loadConfiguration(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	err = json.Unmarshal(b, &config)
	if err != nil {
		return nil, fmt.Errorf("unable to parse config %q: %w", path, err)
	}
	return &config, nil
}

// dropPrivilege drops privileges to those of the specified user.
// If the binary was started by a non-root user then it will not attempt
// to drop privileges.
func dropPrivilege(username string) error {
	if syscall.Getuid() != 0 {
		return nil
	}

	// Lookup.
	user, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("couldn't lookup user %q: %w", username, err)
	}
	uid, err := strconv.Atoi(user.Uid)
	if err != nil {
		return fmt.Errorf("user %q has invalid UID: %w", username, err)
	}
	gid, err := strconv.Atoi(user.Gid)
	if err != nil {
		return fmt.Errorf("user %q has invalid GID: %w", username, err)
	}

	// Drop.
	err = syscall.Setgroups([]int{})
	if err != nil {
		return fmt.Errorf("failed to clear supplemental groups: %w", err)
	}
	err = syscall.Setgid(gid)
	if err != nil {
		return fmt.Errorf("failed to set GID: %w", err)
	}
	err = syscall.Setuid(uid)
	if err != nil {
		return fmt.Errorf("failed to set UID: %w", err)
	}
	return nil
}

// prepareInstance prepares state for a single proxy instance. This includes
// loading TLS key material, preparing the listening socket on the specified
// address/port and preparing a http.Server object.
func prepareInstance(proxyConfig *ProxyConfig, forbidURL *url.URL, testOnly bool) (*ProxyInstance, error) {
	targetURL, err := url.Parse(proxyConfig.Backend)
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL in proxy %q: %w", proxyConfig.Address, err)
	}

	// Make a map of the allowed hosts to speed up lookups later.
	allowedHosts := map[string]bool{}
	for _, h := range proxyConfig.AllowHost {
		allowedHosts[h] = true
	}
	if len(allowedHosts) == 0 {
		return nil, fmt.Errorf("proxy allows no destination hosts")
	}

	var listener net.Listener
	if proxyConfig.TLS {
		cert, err := tls.LoadX509KeyPair(proxyConfig.TLSCert, proxyConfig.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("couldn't load TLS keypair for proxy %q: %w", proxyConfig.Address, err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		if !testOnly {
			listener, err = tls.Listen("tcp4", proxyConfig.Address, tlsConfig)
			if err != nil {
				return nil, fmt.Errorf("couldn't TLS listen at %s: %w", proxyConfig.Address, err)
			}
		}
	} else if !testOnly {
		listener, err = net.Listen("tcp", proxyConfig.Address)
		if err != nil {
			return nil, fmt.Errorf("couldn't TCP listen at %s: %w", proxyConfig.Address, err)
		}
	}
	var responseModifier func(*http.Response) error
	if len(proxyConfig.ResponseSetHeaders) > 0 {
		responseModifier = func(resp *http.Response) error {
			// Don't modify internally-forbidden requests.
			if resp.Request != nil && resp.Request.URL.Host == forbidURL.Host {
				return nil
			}
			for k, v := range proxyConfig.ResponseSetHeaders {
				resp.Header.Set(k, v)
			}
			return nil
		}
	}
	instance := &ProxyInstance{
		ProxyConfig: proxyConfig,
		Listener:    listener,
		Server: &http.Server{
			Handler: &httputil.ReverseProxy{
				// This is where most of the magic (such as it
				// is) happens.
				Rewrite: func(pr *httputil.ProxyRequest) {
					_, ok := allowedHosts[pr.In.Host]
					if !ok {
						pr.SetURL(forbidURL)
						return
					}
					pr.SetXForwarded()
					pr.SetURL(targetURL)
					pr.Out.Host = pr.In.Host
				},
				ModifyResponse: responseModifier,
			},
		},
	}
	return instance, nil
}

// FilteringLogger is a log.Logger that filters out some things we don't care
// about, e.g. clients that never complete a TLS handshake.
type FilteringLogger struct{}

// Write implements the log.Logger contract. It will filter a bunch of stuff
// that is noisy and useless in logs (e.g. clients that disconnect without
// completing TLS handshakes). Cf. https://github.com/golang/go/issues/26918
func (*FilteringLogger) Write(p []byte) (int, error) {
	m := string(p)
	if m == "http: proxy error: context canceled" {
		// Skip.
	} else if strings.HasPrefix(m, "http: TLS handshake error") {
		if strings.HasSuffix(m, ": EOF\n") ||
			strings.HasSuffix(m, "client sent an HTTP request to an HTTPS server") ||
			strings.HasSuffix(m, "read: connection reset by peer") {
			// Skip.
		}
	} else {
		log.Print(m)
	}
	return len(p), nil
}

// newFilteringLogger creates a new FilteringLogger.
func newFilteringLogger() *log.Logger {
	return log.New(&FilteringLogger{}, "", 0)
}

// Forbidden replies to the request with an HTTP 403 Forbidden error.
func Forbidden(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "403 forbidden", http.StatusForbidden)
}

// forbiddenServer returns a http.Server that always returns HTTP 403.
// This server listens on a locally-bound random port, and the addr:port
// for it is returned too.
func forbiddenServer() (*http.Server, net.Listener, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("can't listen locally: %w", err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(Forbidden),
	}
	return server, listener, nil
}

func main() {
	log.SetFlags(0)
	flag.Parse()

	if *showExampleConfig {
		b, err := json.MarshalIndent(exampleConfig, "", "\t")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(b))
		os.Exit(0)
	}

	state := State{Proxies: map[string]*ProxyInstance{}}

	var err error
	state.Config, err = loadConfiguration(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	if len(state.Config.ProxyConfigs) == 0 {
		log.Fatalf("Config %q defines no proxy instances", *configPath)
	}

	// Prepare a server that exists just to forbid requests. We need this
	// because httputil.ReverseProxy doesn't provide any way to refuse a
	// single request.
	var forbidServer *http.Server
	var forbidListener net.Listener
	var forbidURL *url.URL
	if !*configTest && !*configDump {
		forbidServer, forbidListener, err = forbiddenServer()
		if err != nil {
			log.Fatal(err)
		}
		forbidURL, err = url.Parse(fmt.Sprintf("http://%s/", forbidListener.Addr()))
		if err != nil {
			log.Fatalf("internal error: invalid forbidURL: %v", err)
		}
	}

	// Prepare listeners and HTTP proxy servers for each proxy defined
	// in the configuration file.
	for i := range state.Config.ProxyConfigs {
		proxyConfig := &state.Config.ProxyConfigs[i]
		if state.Proxies[proxyConfig.Address] != nil {
			log.Fatalf("Config contains multiple proxies for address %q", proxyConfig.Address)
		}
		instance, err := prepareInstance(proxyConfig, forbidURL, *configTest || *configDump)
		if err != nil {
			log.Fatal(err)
		}
		state.Proxies[proxyConfig.Address] = instance
	}

	// Wrap up now if we're testing/dumping the config.
	if *configTest || *configDump {
		if *configDump {
			b, err := json.MarshalIndent(state.Config, "", "\t")
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(string(b))
		}
		os.Exit(0)
	}

	// Drop privs now that we have all the ports open and all the key
	// material loaded.
	err = dropPrivilege(state.Config.PrivdropUser)
	if err != nil {
		log.Fatalf("Unable to drop privileges to %q: %v", state.Config.PrivdropUser, err)
	}

	// Log runtime errors via syslog unless requested otherwise.
	if !*logToStderr {
		// Default syslog tag is full binary path. This is ugly and not
		// idiomatic, so override.
		progname := filepath.Base(os.Args[0])
		syslogger, err := syslog.Dial("", "", syslog.LOG_ERR|syslog.LOG_DAEMON, progname)
		if err != nil {
			log.Fatalf("Couldn't prepare syslog: %v", err)
		}
		defer syslogger.Close()
		log.SetOutput(syslogger)
	}

	// Arrange to drop some logspam, e.g. clients that EOF before completing
	// the TLS handshake.
	filteringLogger := newFilteringLogger()
	for _, proxy := range state.Proxies {
		proxy.Server.ErrorLog = filteringLogger
	}

	var wg sync.WaitGroup

	// Launch the local server that just 403s.
	log.Printf("listening on %s to forbid requests", forbidListener.Addr())
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := forbidServer.Serve(forbidListener)
		if err != http.ErrServerClosed {
			log.Fatalf("403 server: %v", err)
		}
	}()

	// Launch each proxy in a separate goroutine.
	for listenAddress, proxy := range state.Proxies {
		what := "TCP"
		if proxy.ProxyConfig.TLS {
			what = "TLS"
		}
		log.Printf("listening %s on %v, forwarding to %v", what, listenAddress, proxy.ProxyConfig.Backend)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := proxy.Server.Serve(proxy.Listener)
			if err != http.ErrServerClosed {
				log.Fatalf("proxy at %v: %v", listenAddress, err)
			}
		}()
	}

	// Wire up SIGINT/SIGTERM for graceful shutdown.
	wg.Add(1)
	go func() {
		defer wg.Done()
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint

		// Shut down proxy servers.
		for listenAddress, proxy := range state.Proxies {
			log.Printf("Terminating server on %v", listenAddress)
			if err := proxy.Server.Shutdown(context.Background()); err != nil {
				log.Printf("Error shutting down server %v: %v", listenAddress, err)
			}
		}
		// Shut down 403 server.
		log.Printf("Terminating 403 server on %v", forbidListener.Addr())
		if err := forbidServer.Shutdown(context.Background()); err != nil {
			log.Printf("Error shutting down 403 server: %v", err)
		}
	}()

	wg.Wait()
	log.Printf("all proxies terminated")
	os.Exit(0)
}
