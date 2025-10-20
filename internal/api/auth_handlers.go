package api

import (
	"fmt"
	"log"
	"management-system-api/internal/core"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type registerRequest struct {
	Email                 string `json:"email"`
	Password              string `json:"password"`
	EmailVerificationCode string `json:"emailVerificationCode"`
}

type sendEmailCodeRequest struct {
	Email       string `json:"email"`
	CaptchaCode string `json:"captchaCode"`
}

type loginRequest struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	VerificationCode string `json:"verificationCode"`
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

// RegisterUser API: User registration
func (h *Handler) RegisterUser(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid json"})
		return
	}

	// verify email verificationCode
	verified, err := h.CaptchaManager.VerifyEmailVerificationCode(req.Email, req.EmailVerificationCode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Server internal error"})
		return
	}
	if !verified {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid or expired email verification code."})
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
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

	newId := uuid.New().String()
	usernameParts := strings.Split(newId, "-")
	defaultUsername := "用户" + usernameParts[0] + usernameParts[1]

	// create user
	user := &core.User{
		Id:           newId,
		Username:     defaultUsername,
		Email:        req.Email,
		PasswordHash: string(hash),
	}
	if err := h.Store.CreateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Server internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Registration successful"})
}

// LoginUser API: User login
func (h *Handler) LoginUser(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid json"})
		return
	}

	verified, err := h.CaptchaManager.VerifyAndConsumeToken(req.VerificationCode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Server internal error"})
		return
	}
	if !verified {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid or expired verification code. Please try captcha again."})
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

// Logout API: User logout
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

// SendEmailVerificationCodeHandler API: Send email verification code
func (h *Handler) SendEmailVerificationCodeHandler(c *gin.Context) {
	var req sendEmailCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
		return
	}

	// verify captcha code
	verified, err := h.CaptchaManager.VerifyAndConsumeToken(req.CaptchaCode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Server internal error"})
		return
	}
	if !verified {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid or expired captcha. Please try again."})
		return
	}

	// generate email verification code
	emailCode, err := generateNumericCode(6) // generate 6-digit code
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to generate email code"})
		return
	}

	// store email verification code, effective for 5 minutes
	err = h.CaptchaManager.CreateEmailVerificationCode(req.Email, emailCode, 5*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to save email code"})
		return
	}

	// send email
	subject := "Your Verification Code"
	body := fmt.Sprintf("Welcome! Your verification code is: %s. It will expire in 5 minutes.", emailCode)
	err = h.sendEmail(req.Email, subject, body)
	if err != nil {
		// if sending email fails, log the error but do not inform the user
		log.Printf("Failed to send verification email to %s: %v", req.Email, err)
		// if email sending fails, still return success to avoid email enumeration
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Verification code has been sent to your email if it exists."})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Verification code has been sent to your email."})
}
