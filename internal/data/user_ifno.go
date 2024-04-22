package data

import (
	"time"
)

type UserInfo struct {
	ID             uint      `db:"id"`
	CreatedAt      time.Time `db:"created_at"`
	UpdatedAt      time.Time `db:"updated_at"`
	FName          string    `db:"f_name"`
	SName          string    `db:"s_name"`
	Email          string    `db:"email"`
	PasswordHash   []byte    `db:"password_hash"`
	UserRole       string    `db:"user_role"`
	Activated      bool      `db:"activated"`
	Version        int       `db:"version"`
	ActivationLink string    `db:"ActivationLink"`
}
