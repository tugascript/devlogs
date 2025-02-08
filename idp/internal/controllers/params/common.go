package params

type PaginationQueryParams struct {
	Offset int `json:"offset,omitempty" validate:"min=0"`
	Limit  int `json:"limit,omitempty" validate:"min=1,max=1000"`
}
