package oauthserver

import (
	"errors"
	"fmt"
)

type Authenticator interface {
	Authenticate(username, password string, scope []string) (conf *Config, err error)
}

type FileAuthenticator struct {
}

func NewFileAuthenticator() *FileAuthenticator {
	return &FileAuthenticator{}
}

func (f *FileAuthenticator) Authenticate(username, password string, scope []string) (conf *Config, err error) {
	if username == "admin" && password == "admin" {
		fmt.Println("File authenticate: success")
		return &Config{
			ClientID: 1,
			Scopes:   scope,
		}, nil
	}
	if username == "user" && password == "secret" {
		// Check if the user has asked for any create permission
		for _, s := range scope {
			fmt.Println("asked for: ", s)
			if s == "repository_create" || s == "simulator_create" {
				return nil, errors.New("scope not allowed")
			}
		}
		return &Config{
			ClientID: 2,
			Scopes:   scope,
		}, nil
	}
	fmt.Println("Not success: user", username, "password", password)
	return nil, errors.New("bad")
}
