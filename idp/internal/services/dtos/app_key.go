package dtos

import (
	"encoding/json"
	"errors"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type AppKeyDTO struct {
	id             int
	appID          int
	accountID      int
	name           string
	jwtCryptoSuite string
	publicKey      utils.JWK
	privateKey     string
}

func (ak *AppKeyDTO) ID() int {
	return ak.id
}

func (ak *AppKeyDTO) AppID() int {
	return ak.appID
}

func (ak *AppKeyDTO) AccountID() int {
	return ak.accountID
}

func (ak *AppKeyDTO) Name() string {
	return ak.name
}

func (ak *AppKeyDTO) JWTCryptoSuite() string {
	return ak.jwtCryptoSuite
}

func (ak *AppKeyDTO) PublicKey() utils.JWK {
	return ak.publicKey
}

func (ak *AppKeyDTO) PrivateKey() string {
	return ak.privateKey
}

func decodePublicKeyJSON(jwtCryptoSuite string, publicKey []byte) (utils.JWK, error) {
	switch jwtCryptoSuite {
	case string(tokens.SupportedCryptoSuiteES256):
		jwk := new(utils.ES256JWK)
		if err := json.Unmarshal(publicKey, jwk); err != nil {
			return nil, err
		}
		return jwk, nil
	case string(tokens.SupportedCryptoSuiteEd25519):
		jwk := new(utils.Ed25519JWK)
		if err := json.Unmarshal(publicKey, jwk); err != nil {
			return nil, err
		}
		return jwk, nil
	default:
		return nil, errors.New("unsupported crypto suite")
	}
}

func MapAppKeyToDTO(appKey *database.AppKey) (AppKeyDTO, *exceptions.ServiceError) {
	publicKey, err := decodePublicKeyJSON(appKey.JwtCryptoSuite, appKey.PublicKey)
	if err != nil {
		return AppKeyDTO{}, exceptions.NewServerError()
	}

	return AppKeyDTO{
		id:             int(appKey.ID),
		appID:          int(appKey.AppID),
		accountID:      int(appKey.AccountID),
		name:           appKey.Name,
		jwtCryptoSuite: appKey.JwtCryptoSuite,
		publicKey:      publicKey,
		privateKey:     appKey.PrivateKey,
	}, nil
}
