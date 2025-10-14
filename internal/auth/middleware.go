package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// 在 Context 中使用的键
const ContextUserIDKey = "userID"

// AuthMiddleware 返回一个 gin.HandlerFunc，这是 Gin 中间件的类型
func AuthMiddleware(sm *SessionManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var token string

		// get token from Authorization header first
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.Fields(authHeader)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				token = parts[1]
			}
		}

		// if not found in header, try to get it from cookie
		if token == "" {
			cookie, err := c.Cookie("session_token")
			if err == nil {
				token = cookie
			}
		}

		// if token is still empty, abort with 401
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "message": "illegal request"})
			return
		}

		// validate token
		userID, err := sm.GetUserIDFromToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"success": false, "message": "server internal error"})
			return
		}
		if userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "message": "invalid or expired token"})
			return
		}

		// Verification successful, store userID in context
		c.Set(ContextUserIDKey, userID)
		c.Next()
	}
}
