package utils

import (
	"golang.org/x/crypto/bcrypt"
)

func hashedPassword(password string) (string, error) {
	// factor ofl 10 slows down hackers
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}