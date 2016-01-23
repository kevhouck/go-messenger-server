package main

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Message struct {
	UsernameTo string `json:"user_to"`
	UsernameFrom string `json:"user_from"`
	Content string `json:"content"`
}