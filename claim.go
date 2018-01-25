package oauthserver

type Config struct {
	// ClientID is the application's ID.
	ClientID interface{}

	// Scope specifies optional requested permissions.
	Scopes []string
}

func (c Config) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}
