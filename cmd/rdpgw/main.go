package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/bolkedebruin/gokrb5/v8/keytab"
	"github.com/bolkedebruin/gokrb5/v8/service"
	"github.com/bolkedebruin/gokrb5/v8/spnego"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/kdcproxy"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/web"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/thought-machine/go-flags"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"
)

const (
	gatewayEndPoint  = "/remoteDesktopGateway/"
	kdcProxyEndPoint = "/KdcProxy"
)

var opts struct {
	ConfigFile string `short:"c" long:"conf" default:"rdpgw.yaml" description:"config file (yaml)"`
}

var conf *config.Configuration

func initOIDC(callbackUrl *url.URL, store *web.SessionStore) (*web.OIDC, error) {
	// set oidc config
	provider, err := oidc.NewProvider(context.Background(), conf.OpenId.ProviderUrl)
	if err != nil {
		return nil, fmt.Errorf("Cannot get oidc provider: %w", err)
	}
	oidcConfig := &oidc.Config{
		ClientID: conf.OpenId.ClientId,
	}
	verifier := provider.Verifier(oidcConfig)

	oauthConfig := oauth2.Config{
		ClientID:     conf.OpenId.ClientId,
		ClientSecret: conf.OpenId.ClientSecret,
		RedirectURL:  callbackUrl.String(),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	security.OIDCProvider = provider
	security.Oauth2Config = oauthConfig

	o := web.OIDCConfig{
		OAuth2Config:      &oauthConfig,
		OIDCTokenVerifier: verifier,
		SessionStore:      store,
	}

	return o.New(), nil
}

func main() {
	// set up logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// load config
	_, err := flags.Parse(&opts)
	if err != nil {
		logger.Error("Could not parse command line", "error", err)
		os.Exit(1)
	}
	conf, err = config.Load(opts.ConfigFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Warn("Configuration file not found, using defaults and environment", "config", opts.ConfigFile)
		} else {
			logger.Error("Could not load configuration: %s", "error", err)
			os.Exit(1)
		}
	}

	// set callback url and external advertised gateway address
	url, err := url.Parse(conf.Server.GatewayAddress)
	if err != nil {
		logger.Error("Cannot parse server gateway address", "url", conf.Server.GatewayAddress, "error", err)
		os.Exit(1)
	}
	if url.Scheme == "" {
		url.Scheme = "https"
	}
	url.Path = "callback"

	// set security options
	security.VerifyClientIP = conf.Security.VerifyClientIp
	security.SigningKey = []byte(conf.Security.PAATokenSigningKey)
	security.EncryptionKey = []byte(conf.Security.PAATokenEncryptionKey)
	security.UserEncryptionKey = []byte(conf.Security.UserTokenEncryptionKey)
	security.UserSigningKey = []byte(conf.Security.UserTokenSigningKey)
	security.QuerySigningKey = []byte(conf.Security.QueryTokenSigningKey)
	security.HostSelection = conf.Server.HostSelection
	security.Hosts = conf.Server.Hosts

	// init session store
	logger.Info("Setting up session store", "storage", conf.Server.SessionStore)
	sessionStore, err := web.InitStore([]byte(conf.Server.SessionKey),
		[]byte(conf.Server.SessionEncryptionKey),
		conf.Server.SessionStore,
		conf.Server.MaxSessionLength,
		int(conf.Server.MaxSessionAge.Seconds()),
	)
	if err != nil {
		logger.Error("Could not set up session store", "error", err)
		os.Exit(1)
	}

	// configure web backend
	w := &web.Config{
		QueryInfo:        security.QueryInfo,
		QueryTokenIssuer: conf.Security.QueryTokenIssuer,
		EnableUserToken:  conf.Security.EnableUserToken,
		Hosts:            conf.Server.Hosts,
		HostSelection:    conf.Server.HostSelection,
		RdpOpts: web.RdpOpts{
			UsernameTemplate:    conf.Client.UsernameTemplate,
			SplitUserDomain:     conf.Client.SplitUserDomain,
			NoUsername:          conf.Client.NoUsername,
			AllowQueryUsername:  conf.Client.AllowQueryUsername,
			BandwidthAutoDetect: conf.Client.BandwidthAutoDetect,
			NetworkAutoDetect:   conf.Client.NetworkAutoDetect,
		},
		GatewayAddress: url,
		TemplateFile:   conf.Client.Defaults,
		RdpSigningCert: conf.Client.SigningCert,
		RdpSigningKey:  conf.Client.SigningKey,
		SessionStore:   sessionStore,
		Logger:         logger.With("service", "web"),
	}

	if conf.Caps.TokenAuth {
		w.PAATokenGenerator = security.GeneratePAAToken
	}
	if conf.Security.EnableUserToken {
		w.UserTokenGenerator = security.GenerateUserToken
	}
	h, err := w.NewHandler()
	if err != nil {
		logger.Error("Could not set up web handler", "error", err)
		os.Exit(1)
	}

	logger.Info("Starting remote desktop gateway server")
	cfg := &tls.Config{}

	// configure tls security
	if conf.Server.Tls == config.TlsDisable {
		logger.Warn("TLS disabled - rdp gw connections require tls, make sure to have a terminator")
	} else {
		// auto config
		tlsConfigured := false

		tlsDebug := os.Getenv("SSLKEYLOGFILE")
		if tlsDebug != "" {
			w, err := os.OpenFile(tlsDebug, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				logger.Error("Cannot open key log file", "log", tlsDebug, "error", err)
				os.Exit(1)
			}
			logger.Info("Using key log file", "log", tlsDebug)
			cfg.KeyLogWriter = w
		}

		if conf.Server.KeyFile != "" && conf.Server.CertFile != "" {
			cert, err := tls.LoadX509KeyPair(conf.Server.CertFile, conf.Server.KeyFile)
			if err != nil {
				logger.Warn("Cannot load certfile or keyfile falling back to acme", "error", err, "cert", conf.Server.CertFile, "key", conf.Server.KeyFile)
			}
			cfg.Certificates = append(cfg.Certificates, cert)
			tlsConfigured = true
		}

		if !tlsConfigured {
			logger.Info("Using acme / letsencrypt for tls configuration. Enabling http (port 80) for verification")
			// setup a simple handler which sends a HTHS header for six months (!)
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Strict-Transport-Security", "max-age=15768000 ; includeSubDomains")
				fmt.Fprintf(w, "Hello from RDPGW")
			})

			certMgr := autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(url.Host),
				Cache:      autocert.DirCache("/tmp/rdpgw"),
			}
			cfg.GetCertificate = certMgr.GetCertificate

			go func() {
				http.ListenAndServe(":80", certMgr.HTTPHandler(nil))
			}()
		}
	}

	// gateway confg
	gw, err := protocol.NewGateway(logger.With("service", "gateway"))
	gw.RedirectFlags = protocol.RedirectFlags{
		Clipboard:  conf.Caps.EnableClipboard,
		Drive:      conf.Caps.EnableDrive,
		Printer:    conf.Caps.EnablePrinter,
		Port:       conf.Caps.EnablePort,
		Pnp:        conf.Caps.EnablePnp,
		DisableAll: conf.Caps.DisableRedirect,
		EnableAll:  conf.Caps.RedirectAll,
	}
	gw.IdleTimeout = conf.Caps.IdleTimeout
	gw.SmartCardAuth = conf.Caps.SmartCardAuth
	gw.TokenAuth = conf.Caps.TokenAuth
	gw.ReceiveBuf = conf.Server.ReceiveBuf
	gw.SendBuf = conf.Server.SendBuf

	if conf.Caps.TokenAuth {
		gw.CheckPAACookie = security.CheckPAACookie
		gw.CheckHost = security.CheckSession(security.CheckHost)
	} else {
		gw.CheckHost = security.CheckHost
	}

	r := mux.NewRouter()

	// add favicon handler
	r.HandleFunc("/favicon.ico", h.HandleFavicon)

	// ensure identity is set in context and get some extra info
	r.Use(h.EnrichContext)

	// prometheus metrics
	r.Handle("/metrics", promhttp.Handler())

	// for sso callbacks
	r.HandleFunc("/tokeninfo", web.TokenInfo)

	// gateway endpoint
	rdp := r.PathPrefix(gatewayEndPoint).Subrouter()

	// openid
	if conf.Server.OpenIDEnabled() {
		logger.Info("enabling openid extended authentication")
		o, err := initOIDC(url, sessionStore)
		if err != nil {
			logger.Error("could not set up oidc", "error", err)
		}
		r.Handle("/connect", o.Authenticated(http.HandlerFunc(h.HandleDownload)))
		r.HandleFunc("/callback", o.HandleCallback)

		// only enable un-auth endpoint for openid only config
		if !conf.Server.KerberosEnabled() && !conf.Server.BasicAuthEnabled() && !conf.Server.NtlmEnabled() {
			rdp.Name("gw").HandlerFunc(gw.HandleGatewayProtocol)
		}
	}

	// for stacking of authentication
	auth := web.NewAuthMux()
	rdp.MatcherFunc(web.NoAuthz).HandlerFunc(auth.SetAuthenticate)

	// ntlm
	if conf.Server.NtlmEnabled() {
		logger.Info("enabling NTLM authentication")
		ntlm := web.NTLMAuthHandler{SocketAddress: conf.Server.AuthSocket, Timeout: conf.Server.BasicAuthTimeout}
		rdp.NewRoute().HeadersRegexp("Authorization", "NTLM").HandlerFunc(ntlm.NTLMAuth(gw.HandleGatewayProtocol))
		rdp.NewRoute().HeadersRegexp("Authorization", "Negotiate").HandlerFunc(ntlm.NTLMAuth(gw.HandleGatewayProtocol))
		auth.Register(`NTLM`)
		auth.Register(`Negotiate`)
	}

	// basic auth
	if conf.Server.BasicAuthEnabled() {
		logger.Info("enabling basic authentication")
		q := web.BasicAuthHandler{SocketAddress: conf.Server.AuthSocket, Timeout: conf.Server.BasicAuthTimeout}
		rdp.NewRoute().HeadersRegexp("Authorization", "Basic").HandlerFunc(q.BasicAuth(gw.HandleGatewayProtocol))
		auth.Register(`Basic realm="restricted", charset="UTF-8"`)
	}

	// spnego / kerberos
	if conf.Server.KerberosEnabled() {
		logger.Info("enabling kerberos authentication")
		keytab, err := keytab.Load(conf.Kerberos.Keytab)
		if err != nil {
			logger.Error("Cannot load keytab", "error", err)
			os.Exit(1)
		}
		rdp.NewRoute().HeadersRegexp("Authorization", "Negotiate").Handler(
			spnego.SPNEGOKRB5Authenticate(web.TransposeSPNEGOContext(http.HandlerFunc(gw.HandleGatewayProtocol)),
				keytab,
				service.Logger(log.Default())))

		// kdcproxy
		k := kdcproxy.InitKdcProxy(conf.Kerberos.Krb5Conf)
		r.HandleFunc(kdcProxyEndPoint, k.Handler).Methods("POST")
		auth.Register("Negotiate")
	}

	// setup server
	server := http.Server{
		Addr:         ":" + strconv.Itoa(conf.Server.Port),
		Handler:      r,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // disable http2
	}

	if conf.Server.Tls == config.TlsDisable {
		err = server.ListenAndServe()
	} else {
		err = server.ListenAndServeTLS("", "")
	}
	if err != nil {
		logger.Error("ListenAndServe", "error", err)
		os.Exit(1)
	}
}
