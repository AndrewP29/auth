package main

import (
	"fmt"
	"net/http"

	"github.com/AndrewP29/auth/utils"
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
	http.ListenAndServe(":80080", nil)
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


func login(w http.ResponseWriter, r *http.Request){}


func logout(w http.ResponseWriter, r *http.Request){}


func protected(w http.ResponseWriter, r *http.Request){}

