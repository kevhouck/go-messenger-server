package main

type DBUser struct {
	UserID string `db:"user_id"`
	Username string `db:"username"`
	HashedPassword string `db:"hashed_password"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Message struct {
	UsernameTo string `json:"user_to" db:"username_to"`
	UsernameFrom string `json:"user_from" db:"username_from"`
	Content string `json:"content"`
}