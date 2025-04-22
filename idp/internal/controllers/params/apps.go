package params

type GetAppsQueryParams struct {
	Limit  int    `validate:"min=1,max=100"`
	Offset int    `validate:"min=0"`
	Name   string `validate:"optional,max=50,min=1,alphanum"`
	Order  string `validate:"oneof=date name"`
}
