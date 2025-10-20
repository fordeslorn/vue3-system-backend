package api

import (
	"encoding/base64"
	"fmt"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

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

// GetCaptchaHandler API: Handle get captcha challenge request
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

// VerifyCaptchaHandler API: Handle verify captcha request
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
