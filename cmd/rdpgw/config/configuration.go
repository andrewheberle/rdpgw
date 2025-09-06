package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/hostselection"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

const (
	TlsDisable = "disable"
	TlsAuto    = "auto"

	SessionStoreCookie = "cookie"
	SessionStoreFile   = "file"

	AuthenticationOpenId   = "openid"
	AuthenticationBasic    = "local"
	AuthenticationKerberos = "kerberos"
)

type Configuration struct {
	Server   ServerConfig   `koanf:"server"`
	OpenId   OpenIDConfig   `koanf:"openid"`
	Kerberos KerberosConfig `koanf:"kerberos"`
	Caps     RDGCapsConfig  `koanf:"caps"`
	Security SecurityConfig `koanf:"security"`
	Client   ClientConfig   `koanf:"client"`
}

type ServerConfig struct {
	GatewayAddress       string        `koanf:"gatewayaddress"`
	Port                 int           `koanf:"port"`
	CertFile             string        `koanf:"certfile"`
	KeyFile              string        `koanf:"keyfile"`
	Hosts                []string      `koanf:"hosts"`
	HostSelection        string        `koanf:"hostselection"`
	SessionKey           string        `koanf:"sessionkey"`
	SessionEncryptionKey string        `koanf:"sessionencryptionkey"`
	SessionStore         string        `koanf:"sessionstore"`
	MaxSessionAge        time.Duration `koanf:"maxsessionage"`
	MaxSessionLength     int           `koanf:"maxsessionlength"`
	SendBuf              int           `koanf:"sendbuf"`
	ReceiveBuf           int           `koanf:"receivebuf"`
	Tls                  string        `koanf:"tls"`
	Authentication       []string      `koanf:"authentication"`
	AuthSocket           string        `koanf:"authsocket"`
	BasicAuthTimeout     int           `koanf:"basicauthtimeout"`
}

type KerberosConfig struct {
	Keytab   string `koanf:"keytab"`
	Krb5Conf string `koanf:"krb5conf"`
}

type OpenIDConfig struct {
	ProviderUrl  string `koanf:"providerurl"`
	ClientId     string `koanf:"clientid"`
	ClientSecret string `koanf:"clientsecret"`
}

type RDGCapsConfig struct {
	SmartCardAuth   bool `koanf:"smartcardauth"`
	TokenAuth       bool `koanf:"tokenauth"`
	IdleTimeout     int  `koanf:"idletimeout"`
	RedirectAll     bool `koanf:"redirectall"`
	DisableRedirect bool `koanf:"disableredirect"`
	EnableClipboard bool `koanf:"enableclipboard"`
	EnablePrinter   bool `koanf:"enableprinter"`
	EnablePort      bool `koanf:"enableport"`
	EnablePnp       bool `koanf:"enablepnp"`
	EnableDrive     bool `koanf:"enabledrive"`
}

type SecurityConfig struct {
	PAATokenEncryptionKey  string `koanf:"paatokenencryptionkey"`
	PAATokenSigningKey     string `koanf:"paatokensigningkey"`
	UserTokenEncryptionKey string `koanf:"usertokenencryptionkey"`
	UserTokenSigningKey    string `koanf:"usertokensigningkey"`
	QueryTokenSigningKey   string `koanf:"querytokensigningkey"`
	QueryTokenIssuer       string `koanf:"querytokenissuer"`
	VerifyClientIp         bool   `koanf:"verifyclientip"`
	EnableUserToken        bool   `koanf:"enableusertoken"`
}

type ClientConfig struct {
	Defaults string `koanf:"defaults"`
	// kept for backwards compatibility
	UsernameTemplate    string `koanf:"usernametemplate"`
	SplitUserDomain     bool   `koanf:"splituserdomain"`
	NoUsername          bool   `koanf:"nousername"`
	SigningCert         string `koanf:"signingcert"`
	SigningKey          string `koanf:"signingkey"`
	AllowQueryUsername  bool   `koanf:"allowqueryusername"`
	NetworkAutoDetect   bool   `koanf:"networkautodetect"`
	BandwidthAutoDetect bool   `koanf:"bandwidthautodetect"`
}

func ToCamel(s string) string {
	s = strings.TrimSpace(s)
	n := strings.Builder{}
	n.Grow(len(s))
	var capNext bool = true
	for i, v := range []byte(s) {
		vIsCap := v >= 'A' && v <= 'Z'
		vIsLow := v >= 'a' && v <= 'z'
		if capNext {
			if vIsLow {
				v += 'A'
				v -= 'a'
			}
		} else if i == 0 {
			if vIsCap {
				v += 'a'
				v -= 'A'
			}
		}
		if vIsCap || vIsLow {
			n.WriteByte(v)
			capNext = false
		} else if vIsNum := v >= '0' && v <= '9'; vIsNum {
			n.WriteByte(v)
			capNext = true
		} else {
			capNext = v == '_' || v == ' ' || v == '-' || v == '.'
			if v == '.' {
				n.WriteByte(v)
			}
		}
	}
	return n.String()
}

func Load(configFile string) (*Configuration, error) {
	var configMissing bool
	var conf Configuration

	var k = koanf.New(".")

	if err := k.Load(confmap.Provider(map[string]interface{}{
		"Server.Tls":                 "auto",
		"Server.Port":                443,
		"Server.SessionStore":        "cookie",
		"Server.HostSelection":       hostselection.RoundRobin,
		"Server.Authentication":      "openid",
		"Server.AuthSocket":          "/tmp/rdpgw-auth.sock",
		"Server.BasicAuthTimeout":    5,
		"Server.MaxSessionAge":       time.Minute * 5,
		"Client.NetworkAutoDetect":   1,
		"Client.BandwidthAutoDetect": 1,
		"Security.VerifyClientIp":    true,
		"Caps.TokenAuth":             true,
	}, "."), nil); err != nil {
		return nil, err
	}

	if _, err := os.Stat(configFile); errors.Is(err, os.ErrNotExist) {
		// non fatal error
		configMissing = true
	} else {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("error loading config from file: %w", err)
		}
	}

	if err := k.Load(env.ProviderWithValue("RDPGW_", ".", func(s string, v string) (string, interface{}) {
		key := strings.Replace(strings.ToLower(strings.TrimPrefix(s, "RDPGW_")), "__", ".", -1)
		key = ToCamel(key)

		v = strings.Trim(v, " ")

		// handle lists
		if strings.Contains(v, " ") {
			return key, strings.Split(v, " ")
		}
		return key, v

	}), nil); err != nil {
		return nil, fmt.Errorf("error loading config from environment: %w", err)
	}

	koanfTag := koanf.UnmarshalConf{Tag: "koanf"}
	k.UnmarshalWithConf("Server", &conf.Server, koanfTag)
	k.UnmarshalWithConf("OpenId", &conf.OpenId, koanfTag)
	k.UnmarshalWithConf("Caps", &conf.Caps, koanfTag)
	k.UnmarshalWithConf("Security", &conf.Security, koanfTag)
	k.UnmarshalWithConf("Client", &conf.Client, koanfTag)
	k.UnmarshalWithConf("Kerberos", &conf.Kerberos, koanfTag)

	// check hosts are provided for roundrobin, signed and unsigned
	if slices.Contains([]string{hostselection.RoundRobin, hostselection.Signed, hostselection.Unsigned}, conf.Server.HostSelection) && len(conf.Server.Hosts) == 0 {
		return nil, fmt.Errorf("not enough hosts for host selection algorithm %s", conf.Server.HostSelection)
	}

	log.Printf("hostselection = %s; hosts = %d", conf.Server.HostSelection, len(conf.Server.Hosts))

	if len(conf.Security.PAATokenEncryptionKey) != 32 {
		conf.Security.PAATokenEncryptionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `security.paatokenencryptionkey` specified (empty or not 32 characters). Setting to random")
	}

	if len(conf.Security.PAATokenSigningKey) != 32 {
		conf.Security.PAATokenSigningKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `security.paatokensigningkey` specified (empty or not 32 characters). Setting to random")
	}

	if conf.Security.EnableUserToken {
		if len(conf.Security.UserTokenEncryptionKey) != 32 {
			conf.Security.UserTokenEncryptionKey, _ = security.GenerateRandomString(32)
			log.Printf("No valid `security.usertokenencryptionkey` specified (empty or not 32 characters). Setting to random")
		}
	}

	if len(conf.Server.SessionKey) != 32 {
		conf.Server.SessionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `server.sessionkey` specified (empty or not 32 characters). Setting to random")
	}

	if len(conf.Server.SessionEncryptionKey) != 32 {
		conf.Server.SessionEncryptionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `server.sessionencryptionkey` specified (empty or not 32 characters). Setting to random")
	}

	if conf.Server.HostSelection == "signed" && len(conf.Security.QueryTokenSigningKey) == 0 {
		return nil, fmt.Errorf("host selection is set to `signed` but `querytokensigningkey` is not set")
	}

	if conf.Server.BasicAuthEnabled() && conf.Server.Tls == "disable" {
		return nil, fmt.Errorf("basicauth=local and tls=disable are mutually exclusive")
	}

	if conf.Server.NtlmEnabled() && conf.Server.KerberosEnabled() {
		return nil, fmt.Errorf("ntlm and kerberos authentication are not stackable")
	}

	if !conf.Caps.TokenAuth && conf.Server.OpenIDEnabled() {
		return nil, fmt.Errorf("openid is configured but tokenauth disabled")
	}

	if conf.Server.KerberosEnabled() && conf.Kerberos.Keytab == "" {
		return nil, fmt.Errorf("kerberos is configured but no keytab was specified")
	}

	// prepend '//' if required for URL parsing
	if !strings.Contains(conf.Server.GatewayAddress, "//") {
		conf.Server.GatewayAddress = "//" + conf.Server.GatewayAddress
	}

	// return not exist error back to be handled by caller
	if configMissing {
		return &conf, os.ErrNotExist
	}

	return &conf, nil
}

func (s *ServerConfig) OpenIDEnabled() bool {
	return s.matchAuth("openid")
}

func (s *ServerConfig) KerberosEnabled() bool {
	return s.matchAuth("kerberos")
}

func (s *ServerConfig) BasicAuthEnabled() bool {
	return s.matchAuth("local") || s.matchAuth("basic")
}

func (s *ServerConfig) NtlmEnabled() bool {
	return s.matchAuth("ntlm")
}

func (s *ServerConfig) matchAuth(needle string) bool {
	return slices.Contains(s.Authentication, needle)
}
