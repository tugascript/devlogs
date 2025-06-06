package bodies

type UserData = map[string]any

type CreateUserBody struct {
	Email    string `json:"email" validate:"required,email"`
	Username string `json:"username,omitempty" validate:"optional,min=3,max=100,slug"`
	Password string `json:"password" validate:"required,min=8,max=100,password"`
	UserData
}

type UpdateUserBody struct {
	Email    string `json:"email" validate:"optional,email"`
	Username string `json:"username,omitempty" validate:"optional,min=3,max=100,slug"`
	IsActive bool   `json:"is_active" validate:"optional"`
	UserData
}

type UpdateUserPasswordBody struct {
	Password  string `json:"password" validate:"required,min=8,max=100,password"`
	Password2 string `json:"password2" validate:"required,eqfield=Password"`
}
