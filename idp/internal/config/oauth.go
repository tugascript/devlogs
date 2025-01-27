package config

type OAuthProviderConfig struct {
	clientID     string
	clientSecret string
}

func NewOAuthProvider(clientID, clientSecret string) OAuthProviderConfig {
	return OAuthProviderConfig{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

func (o *OAuthProviderConfig) ClientID() string {
	return o.clientID
}

func (o *OAuthProviderConfig) ClientSecret() string {
	return o.clientSecret
}

type OAuthProvidersConfig struct {
	gitHub    OAuthProviderConfig
	google    OAuthProviderConfig
	facebook  OAuthProviderConfig
	apple     OAuthProviderConfig
	microsoft OAuthProviderConfig
}

func NewOAuthProviders(gitHub, google, facebook, apple, microsoft OAuthProviderConfig) OAuthProvidersConfig {
	return OAuthProvidersConfig{
		gitHub:    gitHub,
		google:    google,
		facebook:  facebook,
		apple:     apple,
		microsoft: microsoft,
	}
}

func (o *OAuthProvidersConfig) GitHub() OAuthProviderConfig {
	return o.gitHub
}

func (o *OAuthProvidersConfig) Google() OAuthProviderConfig {
	return o.google
}

func (o *OAuthProvidersConfig) Facebook() OAuthProviderConfig {
	return o.facebook
}

func (o *OAuthProvidersConfig) Apple() OAuthProviderConfig {
	return o.apple
}

func (o *OAuthProvidersConfig) Microsoft() OAuthProviderConfig {
	return o.microsoft
}
