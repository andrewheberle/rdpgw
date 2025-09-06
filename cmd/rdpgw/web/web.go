package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/maphash"
	"log/slog"
	rnd "math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andrewheberle/rdpsign"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/hostselection"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/rdp"
)

//go:embed favicon.ico
var icon embed.FS

type TokenGeneratorFunc func(context.Context, string, string) (string, error)
type UserTokenGeneratorFunc func(context.Context, string) (string, error)
type QueryInfoFunc func(context.Context, string, string) (string, error)

type Config struct {
	PAATokenGenerator  TokenGeneratorFunc
	UserTokenGenerator UserTokenGeneratorFunc
	QueryInfo          QueryInfoFunc
	QueryTokenIssuer   string
	EnableUserToken    bool
	Hosts              []string
	HostSelection      string
	GatewayAddress     *url.URL
	RdpOpts            RdpOpts
	TemplateFile       string
	RdpSigningCert     string
	RdpSigningKey      string
	SessionStore       *SessionStore
	Logger             *slog.Logger
}

type RdpOpts struct {
	UsernameTemplate    string
	SplitUserDomain     bool
	NoUsername          bool
	AllowQueryUsername  bool
	NetworkAutoDetect   bool
	BandwidthAutoDetect bool
}

type Handler struct {
	paaTokenGenerator  TokenGeneratorFunc
	enableUserToken    bool
	userTokenGenerator UserTokenGeneratorFunc
	queryInfo          QueryInfoFunc
	queryTokenIssuer   string
	gatewayAddress     *url.URL
	hosts              []string
	hostSelection      string
	rdpOpts            RdpOpts
	rdpDefaults        string
	rdpSigner          *rdpsign.Signer
	sessionStore       *SessionStore
	maxAge             int
	logger             *slog.Logger
}

func (c *Config) NewHandler() (*Handler, error) {
	if len(c.Hosts) < 1 && (c.HostSelection != hostselection.Any && c.HostSelection != hostselection.AnySigned) {
		return nil, fmt.Errorf("not enough hosts to connect to specified for %s host selection algorithm", c.HostSelection)
	}

	handler := &Handler{
		paaTokenGenerator:  c.PAATokenGenerator,
		enableUserToken:    c.EnableUserToken,
		userTokenGenerator: c.UserTokenGenerator,
		queryInfo:          c.QueryInfo,
		queryTokenIssuer:   c.QueryTokenIssuer,
		gatewayAddress:     c.GatewayAddress,
		hosts:              c.Hosts,
		hostSelection:      c.HostSelection,
		rdpOpts:            c.RdpOpts,
		rdpDefaults:        c.TemplateFile,
		sessionStore:       c.SessionStore,
	}

	// set up logger
	if c.Logger != nil {
		handler.logger = c.Logger
	} else {
		handler.logger = slog.New(slog.DiscardHandler)
	}

	// set up RDP signer if config values are set
	if c.RdpSigningCert != "" && c.RdpSigningKey != "" {
		signer, err := rdpsign.New(c.RdpSigningCert, c.RdpSigningKey)
		if err != nil {
			return nil, fmt.Errorf("could not set up RDP signer: %w", err)
		}

		handler.rdpSigner = signer
	}

	return handler, nil
}

func (h *Handler) selectRandomHost() string {
	r := rnd.New(rnd.NewSource(int64(new(maphash.Hash).Sum64())))
	host := h.hosts[r.Intn(len(h.hosts))]
	return host
}

func (h *Handler) getUser(ctx context.Context, u *url.URL) (string, error) {
	users, ok := u.Query()["user"]
	if !ok {
		return "", nil
	}

	switch h.hostSelection {
	case hostselection.Signed, hostselection.AnySigned:
		return h.queryInfo(ctx, users[0], h.queryTokenIssuer)
	default:
		return users[0], nil
	}
}

func (h *Handler) getHost(ctx context.Context, u *url.URL) (string, error) {
	switch h.hostSelection {
	case hostselection.RoundRobin:
		return h.selectRandomHost(), nil
	case hostselection.AnySigned:
		hosts, ok := u.Query()["host"]
		if !ok {
			return "", errors.New("invalid query parameter")
		}

		return h.queryInfo(ctx, hosts[0], h.queryTokenIssuer)
	case hostselection.Signed:
		hosts, ok := u.Query()["host"]
		if !ok {
			return "", errors.New("invalid query parameter")
		}
		host, err := h.queryInfo(ctx, hosts[0], h.queryTokenIssuer)
		if err != nil {
			return "", err
		}

		found := false
		for _, check := range h.hosts {
			if check == host {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("invalid host specified: %s", hosts[0])
		}
		return host, nil
	case hostselection.Unsigned:
		hosts, ok := u.Query()["host"]
		if !ok {
			return "", errors.New("invalid query parameter")
		}
		for _, check := range h.hosts {
			if check == hosts[0] {
				return hosts[0], nil
			}
		}
		// not found
		return "", fmt.Errorf("invalid host specified: %s", hosts[0])
	case hostselection.Any:
		hosts, ok := u.Query()["host"]
		if !ok {
			return "", errors.New("invalid query parameter")
		}
		return hosts[0], nil
	default:
		return h.selectRandomHost(), nil
	}
}

func (h *Handler) HandleFavicon(w http.ResponseWriter, r *http.Request) {
	b, err := icon.ReadFile("favicon.ico")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(b)
}

func (h *Handler) HandleDownload(w http.ResponseWriter, r *http.Request) {
	id := identity.FromRequestCtx(r)
	ctx := r.Context()

	opts := h.rdpOpts

	if !id.Authenticated() {
		h.logger.Warn("unauthenticated user", "user", id.UserName())
		http.Error(w, errors.New("cannot find session or user").Error(), http.StatusInternalServerError)
		return
	}

	// determine host to connect to
	host, err := h.getHost(ctx, r.URL)
	if err != nil {
		h.logger.Error("unable to get host from query string", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	host = strings.Replace(host, "{{ preferred_username }}", id.UserName(), 1)
	user := id.UserName()

	render := user
	// if allowed try to set username based on query string value
	if opts.AllowQueryUsername {
		u, err := h.getUser(ctx, r.URL)
		if err != nil {
			h.logger.Error("unable to get user from query string", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		}

		// if set then use it
		if u != "" && u != render {
			render = u
			h.logger.Info("original username changed based on query string parameter", "original", user, "new", render)
		}
	}

	var domain string
	// split username if set
	if opts.SplitUserDomain {
		creds := strings.SplitN(render, "@", 2)
		render = creds[0]
		if len(creds) > 1 {
			domain = creds[1]
		}
	}

	if opts.UsernameTemplate != "" {
		render = fmt.Sprint(opts.UsernameTemplate)
		render = strings.Replace(render, "{{ username }}", user, 1)
		if opts.UsernameTemplate == render {
			h.logger.Error("Invalid username template", "template", opts.UsernameTemplate)
			http.Error(w, errors.New("invalid server configuration").Error(), http.StatusInternalServerError)
			return
		}
	}

	token, err := h.paaTokenGenerator(ctx, user, host)
	if err != nil {
		h.logger.Error("Cannot generate PAA token for user", "error", err, "user", user)
		http.Error(w, errors.New("unable to generate gateway credentials").Error(), http.StatusInternalServerError)
		return
	}

	if h.enableUserToken {
		userToken, err := h.userTokenGenerator(ctx, user)
		if err != nil {
			h.logger.Error("Cannot generate user token for user", "error", err, "user", user)
			http.Error(w, errors.New("unable to generate gateway credentials").Error(), http.StatusInternalServerError)
			return
		}
		render = strings.Replace(render, "{{ token }}", userToken, 1)
	}

	// authenticated
	seed := make([]byte, 16)
	_, err = rand.Read(seed)
	if err != nil {
		h.logger.Error("Cannot generate random seed", "error", err)
		http.Error(w, errors.New("unable to generate random sequence").Error(), http.StatusInternalServerError)
		return
	}
	fn := hex.EncodeToString(seed) + ".rdp"

	w.Header().Set("Content-Disposition", "attachment; filename="+fn)
	w.Header().Set("Content-Type", "application/x-rdp")

	var d *rdp.Builder
	if h.rdpDefaults == "" {
		d = rdp.NewBuilder()
	} else {
		d, err = rdp.NewBuilderFromFile(h.rdpDefaults)
		if err != nil {
			h.logger.Error("Cannot load RDP template file", "file", h.rdpDefaults, "error", err)
			http.Error(w, errors.New("unable to load RDP template").Error(), http.StatusInternalServerError)
			return
		}
	}

	if !opts.NoUsername {
		d.Settings.Username = render
		if domain != "" {
			d.Settings.Domain = domain
		}
	}
	d.Settings.FullAddress = host
	d.Settings.GatewayHostname = h.gatewayAddress.Host
	d.Settings.GatewayCredentialsSource = rdp.SourceCookie
	d.Settings.GatewayAccessToken = token
	d.Settings.GatewayCredentialMethod = 1
	d.Settings.GatewayUsageMethod = 1
	d.Settings.BandwidthAutodetect = h.rdpOpts.BandwidthAutoDetect
	d.Settings.NetworkAutodetect = h.rdpOpts.NetworkAutoDetect

	// no rdp siging so return as-is
	if h.rdpSigner == nil {
		http.ServeContent(w, r, fn, time.Now(), strings.NewReader(d.String()))
		return
	}

	// get rdp content
	rdpContent := d.String()

	// sign rdp content
	signedContent, err := h.rdpSigner.Sign(rdpContent)
	if err != nil {
		h.logger.Error("Could not sign RDP file", "error", err)
		http.Error(w, errors.New("could not sign RDP file").Error(), http.StatusInternalServerError)
		return
	}

	// return signd rdp file
	http.ServeContent(w, r, fn, time.Now(), bytes.NewReader(signedContent))
}
