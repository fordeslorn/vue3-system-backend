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
	DbUrl        string
	RedisAddr    string
	CookieDomain string
}

// LoadConfig 从环境变量中读取配置
func LoadConfig() *Config {
	// set default value for database URL
	dbUrl := os.Getenv("DATABASE_URL")
	if dbUrl == "" {
		dbUrl = "postgresql://root:secret@localhost:5432/simple_bank?sslmode=disable"
	}

	// set default value for Redis address
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	// set default value for cookie domain
	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	if cookieDomain == "" {
		cookieDomain = "localhost"
	}

	return &Config{
		DbUrl:        dbUrl,
		RedisAddr:    redisAddr,
		CookieDomain: cookieDomain,
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
