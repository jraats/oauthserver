package oauthserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

var (
	ConfigCtxKey = &contextKey{"Config"}
	ErrorCtxKey  = &contextKey{"Error"}
)

type Server struct {
	Generator     TokenGenerator
	Authenticator Authenticator
}

func New(generator TokenGenerator, authenticator Authenticator) *Server {
	return &Server{
		Generator:     generator,
		Authenticator: authenticator,
	}
}

func (s *Server) Authenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fmt.Println("Authenticate: not post")
		http.Error(w, http.StatusText(401), 401)
		return
	}
	r.ParseForm()
	if grandType := r.Form.Get("grant_type"); grandType != "client_credentials" {
		fmt.Println("Authenticate: not client_credentials")
		http.Error(w, http.StatusText(401), 401)
		return
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}
	scopes := strings.Split(r.Form.Get("scope"), " ")
	config, err := s.Authenticator.Authenticate(clientID, clientSecret, scopes)
	if err != nil {
		fmt.Println("Authenticate: authenticate error", err)
		http.Error(w, http.StatusText(401), 401)
		return
	}

	token, err := s.Generator.Create(config)

	if token == nil || err != nil {
		fmt.Println("Authenticate: generator error", err)
		http.Error(w, http.StatusText(401), 401)
		return
	}
	b, err := json.Marshal(token)
	if err != nil {
		fmt.Println("Authenticate: marhsal error", err)
		http.Error(w, http.StatusText(500), 500)
		return
	}
	w.Write(b)
}

func (s *Server) FetchToken(next http.Handler) http.Handler {
	hfn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token := headerToken(r)
		config, err := s.Generator.Validate(token)
		ctx = NewContext(ctx, config, err)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(hfn)
}

func (s *Server) RequireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config, err := FromContext(r.Context())

		if err != nil {
			http.Error(w, http.StatusText(401), 401)
			return
		}

		if config == nil {
			http.Error(w, http.StatusText(401), 401)
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}

func (s *Server) RequireTokenScopes(scopes []string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			config, err := FromContext(r.Context())

			if err != nil {
				http.Error(w, http.StatusText(401), 401)
				return
			}

			if config == nil {
				http.Error(w, http.StatusText(401), 401)
				return
			}

			for _, s := range scopes {
				if !config.HasScope(s) {
					http.Error(w, http.StatusText(401), 401)
					return
				}
			}

			// Token is authenticated, pass it through
			next.ServeHTTP(w, r)
		})
	}
}

func headerToken(r *http.Request) string {
	// Get token from authorization header.
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

func NewContext(ctx context.Context, c *Config, err error) context.Context {
	ctx = context.WithValue(ctx, ConfigCtxKey, c)
	ctx = context.WithValue(ctx, ErrorCtxKey, err)
	return ctx
}

func FromContext(ctx context.Context) (*Config, error) {
	config, _ := ctx.Value(ConfigCtxKey).(*Config)
	err, _ := ctx.Value(ErrorCtxKey).(error)

	return config, err
}

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation. This technique
// for defining context keys was copied from Go 1.7's new use of context in net/http.
type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "jwtauth context value " + k.name
}
