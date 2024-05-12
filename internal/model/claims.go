package model

import "github.com/dgrijalva/jwt-go"

type Claims struct {
	Username    string `json:"username"`
	IsActivated bool   `json:"isActivated"`
	Email       string `json:"email"`
	UserId      uint   `json:"userId"`
	ROLE        string `json:"role"`
	jwt.StandardClaims
}
