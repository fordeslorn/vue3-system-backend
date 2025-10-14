package api

import (
	"management-system-api/internal/auth"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, h *Handler) {
	api := r.Group("/api")
	{
		// Public routes
		api.POST("/register", h.RegisterUser)
		api.POST("/login", h.LoginUser)

		// Protected routes, require authentication via middleware
		protected := api.Group("/")
		protected.Use(auth.AuthMiddleware(h.SessionManager))
		{
			protected.GET("/me", h.GetMyProfile)
			protected.POST("/logout", h.Logout)
		}
	}
}
