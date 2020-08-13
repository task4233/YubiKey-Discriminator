package main

import (
	"encoding/hex"
	"fmt"

	"github.com/koesie10/webauthn/webauthn"
)

// User has information for each Yubico
type User struct {
	Name           string                    `json:"name"`
	Authenticators map[string]*Authenticator `json:"-"`
}

// UserAccount has unique `CredentialID` and `Name`, which is the user name.
// The structure can extend member variables.
type UserAccount struct {
	Key  string
	User *User
}

// Authenticator has information related to authentication
type Authenticator struct {
	User         *User
	ID           []byte
	CredentialID []byte
	PublicKey    []byte
	AAGUID       []byte
	SignCount    uint32
}

// Storage stores data for each user
type Storage struct {
	users          map[string]*User
	authenticators map[string]*Authenticator
	userAccounts   []UserAccount
	lastKeyID      string
}

// AddAuthenticator authenticates the user
func (s *Storage) AddAuthenticator(user webauthn.User, authenticator webauthn.Authenticator) error {
	authr := &Authenticator{
		ID:           authenticator.WebAuthID(), // ID is unique ID of PublicKey
		CredentialID: authenticator.WebAuthCredentialID(),
		PublicKey:    authenticator.WebAuthPublicKey(),
		AAGUID:       authenticator.WebAuthAAGUID(),
		SignCount:    authenticator.WebAuthSignCount(),
	}

	key := hex.EncodeToString(authr.ID)

	u, ok := s.users[string(user.WebAuthID())]
	if !ok {
		return fmt.Errorf("user not found")
	}

	if _, ok := s.authenticators[key]; ok {
		return fmt.Errorf("authenticator already exists")
	}

	authr.User = u

	u.Authenticators[key] = authr
	s.authenticators[key] = authr

	return nil
}

// GetAuthenticator gets information for authenticator
func (s *Storage) GetAuthenticator(id []byte) (webauthn.Authenticator, error) {
	authr, ok := s.authenticators[hex.EncodeToString(id)]
	if !ok {
		return nil, fmt.Errorf("authenticator not found")
	}
	return authr, nil
}

// GetAuthenticators get information for authenticators
func (s *Storage) GetAuthenticators(user webauthn.User) ([]webauthn.Authenticator, error) {
	u, ok := s.users[string(user.WebAuthID())]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}

	var authrs []webauthn.Authenticator
	for _, v := range u.Authenticators {
		authrs = append(authrs, v)
	}
	return authrs, nil
}

// WebAuthID implements interface in library
func (u *User) WebAuthID() []byte {
	return []byte(u.Name)
}

// WebAuthName implements interface in library
func (u *User) WebAuthName() string {
	return u.Name
}

// WebAuthDisplayName implements interface in library
func (u *User) WebAuthDisplayName() string {
	return u.Name
}

// WebAuthID implements interface in library
func (a *Authenticator) WebAuthID() []byte {
	return a.ID
}

// WebAuthCredentialID implements interface in library
func (a *Authenticator) WebAuthCredentialID() []byte {
	return a.CredentialID
}

// WebAuthPublicKey implements interface in library
func (a *Authenticator) WebAuthPublicKey() []byte {
	storage.lastKeyID = hex.EncodeToString(a.ID)
	return a.PublicKey
}

// WebAuthAAGUID implements interface in library
func (a *Authenticator) WebAuthAAGUID() []byte {
	return a.AAGUID
}

// WebAuthSignCount implements interface in library
func (a *Authenticator) WebAuthSignCount() uint32 {
	return a.SignCount
}
