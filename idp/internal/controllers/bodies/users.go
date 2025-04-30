package bodies

type CreateUserBody struct {
	Email    string `json:"email" validate:"required,email"`
	Username string `json:"username,omitempty" validate:"optional,min=3,max=100,slug"`
	Password string `json:"password" validate:"required,min=8,max=100,password"`
	DataBody
}
