package config

import (
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/hostselection"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
)

func TestLoad(t *testing.T) {
	randomString, _ := security.GenerateRandomString(32)
	tests := []struct {
		name       string
		env        map[string]string
		configFile string
		// is an error expected
		wantErr bool
		// what error is expected/allowed? nil here means any error if wantErr == true
		allowErr error
		want     *Configuration
	}{
		{"no config (secret keys from env)", map[string]string{
			"RDPGW_SERVER__SESSION_KEY":                randomString,
			"RDPGW_SERVER__HOSTS":                      "10.1.2.3:3389",
			"RDPGW_SERVER__SESSION_ENCRYPTION_KEY":     randomString,
			"RDPGW_SECURITY__PAA_TOKEN_ENCRYPTION_KEY": randomString,
			"RDPGW_SECURITY__PAA_TOKEN_SIGNING_KEY":    randomString,
		}, "", false, os.ErrNotExist, &Configuration{
			Server: ServerConfig{
				GatewayAddress:       "//",
				Tls:                  "auto",
				Port:                 443,
				SessionStore:         "cookie",
				HostSelection:        hostselection.RoundRobin,
				Hosts:                []string{"10.1.2.3:3389"},
				Authentication:       []string{"openid"},
				AuthSocket:           "/tmp/rdpgw-auth.sock",
				BasicAuthTimeout:     5,
				MaxSessionAge:        time.Minute * 5,
				SessionKey:           randomString,
				SessionEncryptionKey: randomString,
			},
			Security: SecurityConfig{
				VerifyClientIp:        true,
				PAATokenEncryptionKey: randomString,
				PAATokenSigningKey:    randomString,
			},
			Caps: RDGCapsConfig{
				TokenAuth: true,
			},
			Client: ClientConfig{
				NetworkAutoDetect:   true,
				BandwidthAutoDetect: true,
			},
		}},
		{"no config (all from env)", map[string]string{
			"RDPGW_SERVER__GATEWAY_ADDRESS":            "https://localhost",
			"RDPGW_SERVER__PORT":                       "8080",
			"RDPGW_SERVER__TLS":                        "disabled",
			"RDPGW_SERVER__HOST_SELECTION":             hostselection.Any,
			"RDPGW_SERVER__HOSTS":                      "10.1.2.3:3389",
			"RDPGW_SERVER__SESSION_KEY":                randomString,
			"RDPGW_SERVER__SESSION_ENCRYPTION_KEY":     randomString,
			"RDPGW_SERVER__MAX_SESSION_AGE":            "1h",
			"RDPGW_SECURITY__PAA_TOKEN_ENCRYPTION_KEY": randomString,
			"RDPGW_SECURITY__PAA_TOKEN_SIGNING_KEY":    randomString,
		}, "", false, os.ErrNotExist, &Configuration{
			Server: ServerConfig{
				GatewayAddress:       "https://localhost",
				Tls:                  "disabled",
				Port:                 8080,
				SessionStore:         "cookie",
				HostSelection:        hostselection.Any,
				Hosts:                []string{"10.1.2.3:3389"},
				Authentication:       []string{"openid"},
				AuthSocket:           "/tmp/rdpgw-auth.sock",
				BasicAuthTimeout:     5,
				MaxSessionAge:        time.Hour,
				SessionKey:           randomString,
				SessionEncryptionKey: randomString,
			},
			Security: SecurityConfig{
				VerifyClientIp:        true,
				PAATokenEncryptionKey: randomString,
				PAATokenSigningKey:    randomString,
			},
			Caps: RDGCapsConfig{
				TokenAuth: true,
			},
			Client: ClientConfig{
				NetworkAutoDetect:   true,
				BandwidthAutoDetect: true,
			},
		}},
		{"invalid config from env", map[string]string{
			"RDPGW_SERVER__GATEWAY_ADDRESS":            "https://localhost",
			"RDPGW_SERVER__PORT":                       "8080",
			"RDPGW_SERVER__TLS":                        "disabled",
			"RDPGW_SERVER__HOST_SELECTION":             hostselection.Unsigned,
			"RDPGW_SERVER__SESSION_KEY":                randomString,
			"RDPGW_SERVER__SESSION_ENCRYPTION_KEY":     randomString,
			"RDPGW_SERVER__MAX_SESSION_AGE":            "5m",
			"RDPGW_SECURITY__PAA_TOKEN_ENCRYPTION_KEY": randomString,
			"RDPGW_SECURITY__PAA_TOKEN_SIGNING_KEY":    randomString,
		}, "", true, nil, nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// set up env
			for k, v := range tt.env {
				os.Setenv(k, v)
			}

			// unset env after
			defer func() {
				for k := range tt.env {
					os.Unsetenv(k)
				}
			}()

			// run test
			got, err := Load(tt.configFile)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Load() = wanted an error, instead got nil")
				}

				if tt.allowErr != nil {
					if !errors.Is(err, tt.allowErr) {
						t.Errorf("Load() = wanted error %v got %v", tt.allowErr, err)
					}
				}
			}
			if !errors.Is(err, tt.allowErr) && !tt.wantErr {
				t.Errorf("Load() = got unexpected error %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Load() = %v, want %v", got, tt.want)
			}
		})
	}
}
