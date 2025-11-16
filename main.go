package main

import (
	"fmt"
	"net/http"
	"time"
)

type Login struct {
	HashedPassword string
	SessionToken string
	CSRFToken string
}


// Key is username
var users = map[string]Login{}

func main() {
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.ListenAndServe(":8008", nil)
}

func register(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid Method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(username) < 6 || len(password) < 6 {
		er := http.StatusNotAcceptable
		http.Error(w, "Either username or password are too short", er)
		return
	}

	if _, ok := users[username]; ok {
		er := http.StatusConflict
		http.Error(w, "User already exists", er)
		return
	}

	hashedPassword, _ := hashedPassword(password)
	users[username] = Login {
		HashedPassword: hashedPassword,
	}

	fmt.Fprintln(w, "User registered successfully")
}


func login(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok || !chackPasswordHash(password, user.HashedPassword) {
		er := http.StatusUnauthorized
		http.Error(w, "Invalid username or password", er)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	//set session cookie
	http.SetCookie(w, &http.Cookie{
		Name: "session_token",
		Value: sessionToken,
		Expires: time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	//set csrf token in a cookie
	http.SetCookie(w, &http.Cookie{
		Name: "csrf_token",
		Value: csrfToken,
		Expires: time.Now().Add(24 * time.Hour),
		HttpOnly: false,
	})

	//Store token in the db
	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	fmt.Fprintln(w, "Login successful!")
}


func logout(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "session_token",
		Value: "",
		Expires: time.Now().Add(-time.Hour),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "csrf_token",
		Value: "",
		Expires: time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	// Clear the tokens from our database
	username := r.FormValue("username")
	user, _ := users[username]
	user.CSRFToken = ""
	users[username] = user
	fmt.Fprintln(w, "Logged out successfully!")
}


func protected(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}

	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}

	username := r.FormValue("username")
	fmt.Fprintf(w, "CSRF validation successful!, Welcome %s\n", username)
}

