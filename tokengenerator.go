package oauthserver

import (
	"errors"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chi/jwtauth"
	"golang.org/x/oauth2"
)

type TokenGenerator interface {
	Create(*Config) (*oauth2.Token, error)
	Validate(token string) (*Config, error)
}

type JWTTokenGenerator struct {
	auth     *jwtauth.JWTAuth
	signer   jwt.SigningMethod
	expireIn time.Duration
}

func NewJWTTokenGenerator(alg string, signKey interface{}, verifyKey interface{}, expireIn time.Duration) *JWTTokenGenerator {
	return &JWTTokenGenerator{
		auth:     jwtauth.New(alg, signKey, verifyKey),
		signer:   jwt.GetSigningMethod(alg),
		expireIn: expireIn,
	}
}

func (j *JWTTokenGenerator) Create(c *Config) (*oauth2.Token, error) {
	claims := make(jwtauth.Claims)
	claims.SetIssuedNow()
	claims.SetExpiryIn(j.expireIn)
	claims.Set("scope", c.Scopes)
	claims.Set("id", c.ClientID)
	_, tokenString, err := j.auth.Encode(claims)
	if err != nil {
		fmt.Println("Create: error encode", err)
		return nil, err
	}
	oToken := &oauth2.Token{
		AccessToken: tokenString,
		Expiry:      time.Now().Add(j.expireIn),
		TokenType:   "bearer",
	}
	return oToken, nil
}

func (j *JWTTokenGenerator) Validate(token string) (*Config, error) {
	jwtToken, err := j.auth.Decode(token)
	if err != nil {
		fmt.Println("Validate error", err, "token:", token)
		return nil, err
	}

	if jwtToken == nil || !jwtToken.Valid || jwtToken.Method != j.signer {
		fmt.Println("Validate: oeps1")
		return nil, errors.New("oeps")
	}

	// Check expiry via "exp" claim
	if jwtauth.IsExpired(jwtToken) {
		fmt.Println("Validate: oeps2", jwtToken)
		return nil, errors.New("oeps")
	}

	// No need for type check because of IsExpired
	claims, _ := jwtToken.Claims.(jwt.MapClaims)
	id, ok := claims["id"]
	if !ok {
		fmt.Println("Validate: oeps3")
		return nil, errors.New("oeps")
	}

	scopesInterface, ok := claims["scope"]
	if !ok {
		fmt.Println("Validate: oeps4")
		return nil, errors.New("oeps")
	}
	scopes, err := extractScope(scopesInterface)
	if err != nil {
		return nil, err
	}

	return &Config{
		ClientID: id,
		Scopes:   scopes,
	}, nil
}

func extractScope(s interface{}) ([]string, error) {
	scopes, ok := s.([]interface{})
	if !ok {
		return nil, errors.New("oeps")
	}

	res := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		s, ok := scope.(string)
		if !ok {
			return nil, errors.New("oeps")
		}
		res = append(res, s)
	}
	return res, nil
}
