package api

import (
	"management-system-api/internal/auth"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetMyProfile API: Get user profile
func (h *Handler) GetMyProfile(c *gin.Context) {
	// get userID from context
	userID, exists := c.Get(auth.ContextUserIDKey)
	if !exists {
		// It should not happen if middleware is correctly set
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "failed to get user info"})
		return
	}

	// query user from db
	user, err := h.Store.GetByID(userID.(string))
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"user": gin.H{
			"id":       user.Id,
			"username": user.Username,
			"email":    user.Email,
		},
	})
}
