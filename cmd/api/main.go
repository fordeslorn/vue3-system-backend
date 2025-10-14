package main

import (
	"log"
	"management-system-api/config"
	"management-system-api/internal/api"
	"management-system-api/internal/store"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Initialize database connection
	db := config.NewDB()
	// Ensure the database connection is closed on exit
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("failed to close database: %v", err)
		}
	}()

	// Create Gin engine
	r := gin.Default()

	// Create store and handler
	userStore := store.NewStore(db)
	handler := api.NewHandler(userStore)

	// Register routes
	api.RegisterRoutes(r, handler)

	// Start server
	log.Println("Starting server on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
