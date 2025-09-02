package web

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/gorilla/sessions"
)

const (
	rdpGwSession     = "RDPGWSESSION"
	identityKey      = "RDPGWID"
	maxSessionLength = 8192
	MaxAge           = 120
)

type SessionStore struct {
	store  sessions.Store
	maxAge int
}

func InitStore(sessionKey []byte, encryptionKey []byte, storeType string, maxLength int, maxAge int) (*SessionStore, error) {
	if len(sessionKey) < 32 {
		return nil, fmt.Errorf("session key too small: %d", len(sessionKey))
	}
	if len(encryptionKey) < 32 {
		return nil, fmt.Errorf("encryption key too small: %d", len(encryptionKey))
	}

	if storeType == "file" {
		log.Println("Filesystem is used as session storage")
		fs := sessions.NewFilesystemStore(os.TempDir(), sessionKey, encryptionKey)
		fs.MaxAge(maxAge)

		// set max length
		if maxLength == 0 {
			maxLength = maxSessionLength
		}
		log.Printf("Setting maximum session storage to %d bytes", maxLength)
		fs.MaxLength(maxLength)

		return &SessionStore{fs, maxAge}, nil
	}

	log.Println("Cookies are used as session storage")
	cs := sessions.NewCookieStore(sessionKey, encryptionKey)
	cs.MaxAge(maxAge)

	return &SessionStore{cs, maxAge}, nil
}

func (ss *SessionStore) GetSessionIdentity(r *http.Request) (identity.Identity, error) {
	s, err := ss.store.Get(r, rdpGwSession)
	if err != nil {
		return nil, err
	}

	idData := s.Values[identityKey]
	if idData == nil {
		return nil, nil

	}
	id := identity.NewUser()
	id.Unmarshal(idData.([]byte))
	return id, nil
}

func (ss *SessionStore) SaveSessionIdentity(r *http.Request, w http.ResponseWriter, id identity.Identity) error {
	session, err := ss.store.Get(r, rdpGwSession)
	if err != nil {
		return err
	}
	session.Options.MaxAge = ss.maxAge

	idData, err := id.Marshal()
	if err != nil {
		return err
	}
	session.Values[identityKey] = idData

	return ss.store.Save(r, w, session)

}
