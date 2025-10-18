package auth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// CaptchaSessionData 存储在 Redis 中的验证码会话信息
type CaptchaSessionData struct {
	CorrectIDs map[string]bool `json:"correct_ids"`
}

// CaptchaManager 负责管理验证码的生成、存储和验证
type CaptchaManager struct {
	redisClient *redis.Client
	ctx         context.Context
}

// Constructor for CaptchaManager
func NewCaptchaManager(redisClient *redis.Client) *CaptchaManager {
	return &CaptchaManager{
		redisClient: redisClient,
		ctx:         context.Background(),
	}
}

// CreateCaptchaSession 创建一个新的验证码会话，并将正确答案存入 Redis
func (cm *CaptchaManager) CreateCaptchaSession(correctIDs []string, duration time.Duration) (string, error) {
	sessionID := "captcha:" + uuid.New().String() // 使用前缀以区分
	idSet := make(map[string]bool)
	for _, id := range correctIDs {
		idSet[id] = true
	}

	data, err := json.Marshal(CaptchaSessionData{CorrectIDs: idSet})
	if err != nil {
		return "", err
	}

	err = cm.redisClient.Set(cm.ctx, sessionID, data, duration).Err()
	if err != nil {
		return "", err
	}
	return sessionID, nil
}

// GetCaptchaSession 从 Redis 获取验证码会话数据
func (cm *CaptchaManager) GetCaptchaSession(sessionID string) (*CaptchaSessionData, error) {
	data, err := cm.redisClient.Get(cm.ctx, sessionID).Result()
	if err == redis.Nil {
		return nil, nil // 会话不存在或已过期
	} else if err != nil {
		return nil, err
	}

	var sessionData CaptchaSessionData
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		return nil, err
	}
	return &sessionData, nil
}

// DeleteCaptchaSession 从 Redis 删除一个验证码会话
func (cm *CaptchaManager) DeleteCaptchaSession(sessionID string) error {
	return cm.redisClient.Del(cm.ctx, sessionID).Err()
}

// CreateVerificationToken 创建一个一次性的验证票据，用于后续的注册/登录请求
func (cm *CaptchaManager) CreateVerificationToken(duration time.Duration) (string, error) {
	token := "verify_token:" + uuid.New().String()
	// 存储一个简单的值，比如 "1"，并设置短暂的有效期
	err := cm.redisClient.Set(cm.ctx, token, "1", duration).Err()
	if err != nil {
		return "", err
	}
	return token, nil
}

// VerifyAndConsumeToken 验证票据是否存在，如果存在则立即删除（消费掉）
func (cm *CaptchaManager) VerifyAndConsumeToken(token string) (bool, error) {
	deletedCount, err := cm.redisClient.Del(cm.ctx, token).Result()
	if err != nil {
		return false, err
	}
	return deletedCount > 0, nil
}
