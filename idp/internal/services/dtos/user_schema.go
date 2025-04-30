package dtos

import (
	"encoding/json"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

func MapUserSchemaToDTO(userSchema *database.UserSchema) (SchemaDTO, *exceptions.ServiceError) {
	var schema SchemaDTO
	if err := json.Unmarshal(userSchema.SchemaData, &schema); err != nil {
		return nil, exceptions.NewServerError()
	}
	return schema, nil
}
