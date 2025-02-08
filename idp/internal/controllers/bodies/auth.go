package bodies

type RegisterAccountBody struct {
	Email     string `json:"email" validate:"required,email"`
	FirstName string `json:"first_name" validate:"required,min=2,max=50"`
	LastName  string `json:"last_name" validate:"required,min=2,max=50"`
	Password  string `json:"password" validate:"required,min=8,max=100,password"`
	Password2 string `json:"password2" validate:"required,eqfield=Password"`
}
