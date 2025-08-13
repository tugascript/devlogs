package bodies

type UserData = map[string]any

type CreateUserBody struct {
	Email    string `json:"email" validate:"required,email,max=250"`
	Username string `json:"username,omitempty" validate:"omitempty,min=3,max=63,slug"`
	Password string `json:"password" validate:"required,min=8,max=100,password"`
	UserData
}

type UpdateUserBody struct {
	Email    string `json:"email" validate:"omitempty,email,max=250"`
	Username string `json:"username,omitempty" validate:"omitempty,min=3,max=63,slug"`
	IsActive bool   `json:"is_active"`
	UserData
}

type UpdateUserPasswordBody struct {
	Password  string `json:"password" validate:"required,min=8,max=100,password"`
	Password2 string `json:"password2" validate:"required,eqfield=Password"`
}

type UpdateAccountUsernameBody struct {
	Username string `json:"username" validate:"required,min=3,max=63,slug"`
	Password string `json:"password,omitempty" validate:"omitempty,min=1"`
}
