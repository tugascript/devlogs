package routes

import (
	"github.com/tugascript/devlogs/idp/internal/controllers"
)

type Routes struct {
	controllers *controllers.Controllers
}

func NewRoutes(ctrls *controllers.Controllers) *Routes {
	return &Routes{controllers: ctrls}
}
