package main

import (
	"log"
	"management-system-api/config"
	"management-system-api/internal/api"
	"management-system-api/internal/auth"
	"management-system-api/internal/store"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// load config
	cfg := config.LoadConfig()

	// Initialize database connection
	db := config.NewDB(cfg.DbUrl)
	// Ensure the database connection is closed on exit
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("failed to close database: %v", err)
		}
	}()

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	// Create Gin engine
	r := gin.Default()

	// configure CORS middleware
	r.Use(cors.New(cors.Config{
		// allow origins from config, * means allow all, in production should specify your frontend domain
		AllowOrigins: strings.Split(cfg.CorsAllowedOrigins, ","),
		// allow methods that can be used by the client
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		// allow headers that can be sent by the client
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization"},
		// allow headers that can be exposed to the browser
		ExposeHeaders: []string{"Content-Length"},
		// allow cookies
		AllowCredentials: true,
		// set preflight request cache duration
		MaxAge: 12 * time.Hour,
	}))

	// Create store and handler
	userStore := store.NewStore(db)
	sessionManager := auth.NewSessionManager(redisClient)
	handler := api.NewHandler(userStore, sessionManager, cfg.CookieDomain)
	// Register routes
	api.RegisterRoutes(r, handler)

	// Start server
	log.Println("\033[34mStarting server on :8080\033[0m")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
