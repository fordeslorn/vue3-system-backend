package api

import "github.com/gin-gonic/gin"

func RegisterRoutes(r *gin.Engine, h *Handler) {
	api := r.Group("/api")
	{
		api.POST("/register", h.RegisterUser)

		api.POST("/login", h.LoginUser)
		// 之后添加  /me /logout

	}
}
