package bodies

type SchemaFieldBody struct {
	Type     string `json:"type" validate:"required,oneof=string int float bool"`
	Unique   bool   `json:"unique,omitempty"`
	Required bool   `json:"required,omitempty"`
	Default  any    `json:"default,omitempty"`
}
