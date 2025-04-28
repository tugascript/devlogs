package services

type SchemaField struct {
	Type     string `json:"type"`
	Unique   bool   `json:"unique"`
	Required bool   `json:"required"`
	Default  any    `json:"default,omitempty"`
}
