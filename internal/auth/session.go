package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/redis/go-redis/v9"
)

type SessionManager struct {
	redisClient *redis.Client
	ctx         context.Context
}

// Create a new SessionManager
func NewSessionManager(redisClient *redis.Client) *SessionManager {
	return &SessionManager{
		redisClient: redisClient,
		ctx:         context.Background(),
	}
}

// Create a new session for a user
func (sm *SessionManager) CreateSession(userID string, duration time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	sessionToken := hex.EncodeToString(b)

	err := sm.redisClient.Set(sm.ctx, sessionToken, userID, duration).Err()
	if err != nil {
		return "", err
	}

	return sessionToken, nil
}

// Get user ID from session token
func (sm *SessionManager) GetUserIDFromToken(sessionToken string) (string, error) {
	userID, err := sm.redisClient.Get(sm.ctx, sessionToken).Result()
	if err == redis.Nil {
		return "", nil
	} else if err != nil {
		return "", err
	}
	return userID, nil
}

// Delete a session
func (sm *SessionManager) DeleteSession(sessionToken string) error {
	return sm.redisClient.Del(sm.ctx, sessionToken).Err()
}
