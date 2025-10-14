package api

import "github.com/gin-gonic/gin"

func RegisterRoutes(r *gin.Engine, h *Handler) {
	api := r.Group("/api")
	{
		api.POST("/register", h.RegisterUser)
		// 之后添加 /login /me /logout
	}
}
