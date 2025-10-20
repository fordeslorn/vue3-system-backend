package api

import (
	"management-system-api/internal/auth"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, h *Handler) {
	api := r.Group("/api/v1")
	{
		// Public routes
		authGroup := api.Group("/auth")
		{
			authGroup.POST("/register", h.RegisterUser)
			authGroup.POST("/login", h.LoginUser)
			authGroup.GET("/captcha", h.GetCaptchaHandler)
			authGroup.POST("/captcha", h.VerifyCaptchaHandler)
			authGroup.POST("/email-verification", h.SendEmailVerificationCodeHandler)
		}

		// Protected routes, require authentication via middleware
		protected := api.Group("/")
		protected.Use(auth.AuthMiddleware(h.SessionManager))
		{
			protected.GET("/me", h.GetMyProfile)
			protected.POST("/logout", h.Logout)
		}
	}
}
