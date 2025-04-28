package dtos

import (
	"encoding/json"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type UserSchemaFieldDTO struct {
	Type     string `json:"type"`
	Unique   bool   `json:"unique"`
	Required bool   `json:"required"`
	Default  any    `json:"default,omitempty"`
}

type UserSchemaDTO map[string]UserSchemaFieldDTO

func MapUserSchemaToDTO(userSchema *database.UserSchema) (UserSchemaDTO, *exceptions.ServiceError) {
	var schema UserSchemaDTO
	if err := json.Unmarshal(userSchema.SchemaData, &schema); err != nil {
		return nil, exceptions.NewServerError()
	}
	return schema, nil
}
