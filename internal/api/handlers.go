package api

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"management-system-api/config"
	"management-system-api/internal/auth"
	"management-system-api/internal/core"
	"management-system-api/internal/store"
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jordan-wright/email"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	Store          *store.Store
	SessionManager *auth.SessionManager
	CaptchaManager *auth.CaptchaManager
	CookieDomain   string
	SmtpHost       string
	SmtpPort       string
	SmtpUser       string
	SmtpPass       string
}

func NewHandler(s *store.Store, sm *auth.SessionManager, cm *auth.CaptchaManager, cfg *config.Config) *Handler {
	return &Handler{
		Store:          s,
		SessionManager: sm,
		CaptchaManager: cm,
		CookieDomain:   cfg.CookieDomain,
		SmtpHost:       cfg.SmtpHost,
		SmtpPort:       cfg.SmtpPort,
		SmtpUser:       cfg.SmtpUser,
		SmtpPass:       cfg.SmtpPass,
	}
}

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

type CaptchaImage struct {
	ID   string `json:"id"`
	Data string `json:"data"`
}

type CaptchaChallenge struct {
	SessionID string         `json:"sessionId"`
	Images    []CaptchaImage `json:"images"`
}

type VerifyCaptchaRequest struct {
	SessionID   string   `json:"sessionId"`
	SelectedIDs []string `json:"selectedIds"`
}

type VerifyCaptchaResponse struct {
	Code string `json:"code"`
}

///////////////////////////////////////////////////////////////////////////////////

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

// API: User registration
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

// API: User login
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

// API: Get user profile
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

// API: User logout
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

////////////////////////////////////////////////////////////////////////////
/**
Captcha related handlers
*/

// read all image files from a directory
func readImagesFromDir(dir string) ([]string, error) {
	var files []string
	allowed := map[string]bool{
		".png":  true,
		".jpg":  true,
		".jpeg": true,
		".gif":  true,
		".webp": true,
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(info.Name()))
			if allowed[ext] {
				files = append(files, path)
			}
		}
		return nil
	})
	return files, err
}

// encode image file to base64 data URI
func encodeImageToBase64(filePath string) (string, error) {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(bytes)
	ext := strings.ToLower(filepath.Ext(filePath))
	mimeType := "image/jpeg"
	switch ext {
	case ".png":
		mimeType = "image/png"
	case ".gif":
		mimeType = "image/gif"
	case ".webp":
		mimeType = "image/webp"
	case ".svg":
		mimeType = "image/svg+xml"
	case ".jpg", ".jpeg":
		mimeType = "image/jpeg"
	}
	return fmt.Sprintf("data:%s;base64,%s", mimeType, encoded), nil
}

// API: Handle get captcha challenge request
func (h *Handler) GetCaptchaHandler(c *gin.Context) {
	correctCount := mrand.Intn(3) + 1
	const totalCount = 4

	correctDir := "./assets/captcha_images/white"
	distractorDir := "./assets/captcha_images/other"

	correctFiles, err := readImagesFromDir(correctDir)
	if err != nil || len(correctFiles) < correctCount {
		log.Printf("Error loading correct captcha images: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Server internal error"})
		return
	}

	distractorFiles, err := readImagesFromDir(distractorDir)
	if err != nil || len(distractorFiles) < (totalCount-correctCount) {
		log.Printf("Error loading distractor captcha images: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Server internal error"})
		return
	}

	mrand.Shuffle(len(correctFiles), func(i, j int) { correctFiles[i], correctFiles[j] = correctFiles[j], correctFiles[i] })
	mrand.Shuffle(len(distractorFiles), func(i, j int) { distractorFiles[i], distractorFiles[j] = distractorFiles[j], distractorFiles[i] })

	selectedCorrect := correctFiles[:correctCount]
	selectedDistractor := distractorFiles[:totalCount-correctCount]

	var allImages []CaptchaImage
	var correctIDs []string

	for _, file := range selectedCorrect {
		base64Data, err := encodeImageToBase64(file)
		if err != nil {
			continue
		}
		imgID := uuid.New().String()
		allImages = append(allImages, CaptchaImage{ID: imgID, Data: base64Data})
		correctIDs = append(correctIDs, imgID)
	}

	for _, file := range selectedDistractor {
		base64Data, err := encodeImageToBase64(file)
		if err != nil {
			continue
		}
		imgID := uuid.New().String()
		allImages = append(allImages, CaptchaImage{ID: imgID, Data: base64Data})
	}

	mrand.Shuffle(len(allImages), func(i, j int) { allImages[i], allImages[j] = allImages[j], allImages[i] })

	sessionID, err := h.CaptchaManager.CreateCaptchaSession(correctIDs, 5*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Server internal error"})
		return
	}

	c.JSON(http.StatusOK, CaptchaChallenge{
		SessionID: sessionID,
		Images:    allImages,
	})
}

// API: Handle verify captcha request
func (h *Handler) VerifyCaptchaHandler(c *gin.Context) {
	var req VerifyCaptchaRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
		return
	}

	session, err := h.CaptchaManager.GetCaptchaSession(req.SessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Server internal error"})
		return
	}
	if session == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Captcha expired, please refresh"})
		return
	}

	// Delete the session after retrieval to prevent reuse
	_ = h.CaptchaManager.DeleteCaptchaSession(req.SessionID)

	if len(req.SelectedIDs) != len(session.CorrectIDs) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Verification failed, please try again"})
		return
	}

	sort.Strings(req.SelectedIDs)
	correctIDsSlice := make([]string, 0, len(session.CorrectIDs))
	for id := range session.CorrectIDs {
		correctIDsSlice = append(correctIDsSlice, id)
	}
	sort.Strings(correctIDsSlice)

	for i := range req.SelectedIDs {
		if req.SelectedIDs[i] != correctIDsSlice[i] {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Verification failed, please try again"})
			return
		}
	}

	// Verification successful, create a verification code
	verificationCode, err := h.CaptchaManager.CreateVerificationToken(1 * time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to generate verification code"})
		return
	}

	c.JSON(http.StatusOK, VerifyCaptchaResponse{Code: verificationCode})
}

//////////////////////////////////////////////////////////////////////////////

// generate a numeric code of given length
func generateNumericCode(length int) (string, error) {
	const letters = "0123456789"
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		result[i] = letters[num.Int64()]
	}
	return string(result), nil
}

// API: Send email verification code
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
	emailCode, err := generateNumericCode(6) // 生成一个6位数字验证码
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

	// 步骤 4: 发送邮件 (重要提示：这里只是打印到控制台，您需要替换为真实的邮件发送服务)
	subject := "Your Verification Code"
	body := fmt.Sprintf("Welcome! Your verification code is: %s. It will expire in 5 minutes.", emailCode)
	err = h.sendEmail(req.Email, subject, body)
	if err != nil {
		// 如果邮件发送失败，不应让用户知道具体错误，记录日志即可
		log.Printf("Failed to send verification email to %s: %v", req.Email, err)
		// 即使发送失败，也返回成功，避免攻击者利用此接口探测邮箱是否存在
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Verification code has been sent to your email if it exists."})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Verification code has been sent to your email."})
}

// sendEmail 使用 SMTP 发送邮件
func (h *Handler) sendEmail(to, subject, body string) error {
	e := email.NewEmail()
	e.From = h.SmtpUser
	e.To = []string{to}
	e.Subject = subject
	e.Text = []byte(body)

	addr := h.SmtpHost + ":" + h.SmtpPort
	// 该库的 Send 方法会自动处理 STARTTLS
	// 它使用 net/smtp.PlainAuth，但其内部实现能更好地与需要 STARTTLS 的服务器协作
	err := e.Send(addr, smtp.PlainAuth("", h.SmtpUser, h.SmtpPass, h.SmtpHost))
	if err != nil {
		// 错误日志已包含在函数内部，这里只返回错误
		return err
	}

	log.Printf("Email sent successfully to %s", to)
	return nil
}
