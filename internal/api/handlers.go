package api

import (
	"management-system-api/internal/auth"
	"management-system-api/internal/core"
	"management-system-api/internal/store"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	Store          *store.Store
	SessionManager *auth.SessionManager
	CookieDomain   string
}

func NewHandler(s *store.Store, sm *auth.SessionManager, cookieDomain string) *Handler {
	return &Handler{
		Store:          s,
		SessionManager: sm,
		CookieDomain:   cookieDomain,
	}
}

type registerRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Password validation: at least 8 chars, at least one upper, one lower, one digit
func validatePassword(pw string) bool {
	if len(pw) < 8 {
		return false
	}
	var hasUpper, hasLower, hasDigit bool
	for _, char := range pw {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		}
	}
	return hasUpper && hasLower && hasDigit
}

// User registration api
func (h *Handler) RegisterUser(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid json"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	if req.Username == "" || req.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Email and username cannot be empty"})
		return
	}

	// validate password
	if !validatePassword(req.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Password must be at least 8 characters long and include uppercase, lowercase letters, and digits"})
		return
	}

	// check existing
	existing, err := h.Store.GetByEmail(req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Server internal error"})
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"success": false, "message": "email exists"})
		return
	}

	// hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Server internal error"})
		return
	}

	// create user
	user := &core.User{
		Id:           uuid.New().String(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hash),
	}
	if err := h.Store.CreateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Server internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Registration successful"})
}

// User login api
func (h *Handler) LoginUser(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid json"})
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Email and password cannot be empty"})
		return
	}

	// check existing
	user, err := h.Store.GetByEmail(req.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Invalid email or password"})
		return
	}
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Invalid email or password"})
		return
	}

	// compare password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Invalid email or password"})
		return
	}

	// Create session
	sessionToken, err := h.SessionManager.CreateSession(user.Id, 24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Server internal error"})
		return
	}

	// set cookie
	c.SetCookie("session_token", sessionToken, 86400, "/", h.CookieDomain, false, true)

	// Success login
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"user": gin.H{
			"id":       user.Id,
			"username": user.Username,
		},
	})
}

// Get user profile api
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

// User logout api
func (h *Handler) Logout(c *gin.Context) {
	// get session token from cookie
	token, err := c.Cookie("session_token")
	if err != nil {
		// if no cookie, just return success
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "logged out"})
		return
	}

	// delete session from redis
	_ = h.SessionManager.DeleteSession(token)

	// clear cookie
	c.SetCookie("session_token", "", -1, "/", h.CookieDomain, false, true)

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "logged out successfully"})
}
