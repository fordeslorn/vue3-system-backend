package config

import (
	"database/sql"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

// Config stores the application configuration
type Config struct {
	DbUrl              string
	RedisAddr          string
	CookieDomain       string
	CorsAllowedOrigins string
	SmtpHost           string // 新增: SMTP 服务器地址
	SmtpPort           string // 新增: SMTP 服务器端口
	SmtpUser           string // 新增: SMTP 登录用户名 (通常是邮箱地址)
	SmtpPass           string // 新增: SMTP 登录密码或授权码
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// LoadConfig 从环境变量中读取配置
func LoadConfig() *Config {
	return &Config{
		DbUrl:              getEnv("DATABASE_URL", "postgres://user:password@localhost/dbname?sslmode=disable"),
		RedisAddr:          getEnv("REDIS_ADDR", "localhost:6379"),
		CorsAllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000"),
		CookieDomain:       getEnv("COOKIE_DOMAIN", "localhost"),
		SmtpHost:           getEnv("SMTP_HOST", "smtp.example.com"), // 新增
		SmtpPort:           getEnv("SMTP_PORT", "587"),              // 新增
		SmtpUser:           getEnv("SMTP_USER", "user@example.com"), // 新增
		SmtpPass:           getEnv("SMTP_PASS", "your-password"),    // 新增
	}
}

func NewDB(dsn string) *sql.DB {
	if dsn == "" {
		log.Fatal("DATABASE_URL not set in environment")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}

	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
	return db
}
