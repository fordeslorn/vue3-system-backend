package api

import (
	"crypto/rand"
	"fmt"
	"log"
	"management-system-api/config"
	"management-system-api/internal/auth"
	"management-system-api/internal/store"
	"math/big"
	"net/smtp"

	"github.com/jordan-wright/email"
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

//////////////////////////////////////////////////////////////////////////////////
// general helper functions

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

// sendEmail 使用 SMTP 发送邮件
func (h *Handler) sendEmail(to, subject, body string) error {
	e := email.NewEmail()
	e.From = fmt.Sprintf("Vue3 System<%s>", h.SmtpUser)
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
