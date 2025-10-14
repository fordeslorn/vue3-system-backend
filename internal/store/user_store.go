package store

// Package store handles all database interactions related to users.

import (
	"database/sql"

	"management-system-api/internal/core"
)

type Store struct {
	DB *sql.DB
}

// Constructor for Store
func NewStore(db *sql.DB) *Store { return &Store{DB: db} }

func (s *Store) CreateUser(u *core.User) error {
	_, err := s.DB.Exec(
		"INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)",
		u.Id, u.Username, u.Email, u.PasswordHash,
	)
	return err
}

func (s *Store) GetByEmail(email string) (*core.User, error) {
	u := &core.User{}
	err := s.DB.QueryRow("SELECT id, username, email, password_hash FROM users WHERE email = $1", email).
		Scan(&u.Id, &u.Username, &u.Email, &u.PasswordHash)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) GetByID(id string) (*core.User, error) {
	u := &core.User{}

	err := s.DB.QueryRow("SELECT id, username, email FROM users WHERE id = $1", id).
		Scan(&u.Id, &u.Username, &u.Email)

	if err == sql.ErrNoRows {
		return nil, nil // User not found
	}
	if err != nil {
		return nil, err // Error occurred in query
	}
	return u, nil
}
