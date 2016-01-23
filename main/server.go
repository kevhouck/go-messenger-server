package main

import (
	"github.com/jmoiron/sqlx"
	_"github.com/lib/pq"
	"github.com/gorilla/mux"
	"net/http"
	"fmt"
	"log"
	"github.com/codegangsta/negroni"
)

var schema = `
CREATE TABLE users (
	user_id serial primary key,
	username text UNIQUE,
	hashed_password text
);

CREATE TABLE messages (
	messege_id serial primary key,
	user_to serial references users(user_id),
	user_from serial references users(user_id),
	content text
);`

var db *sqlx.DB

func main() {
	var err error
	db, err = sqlx.Connect("postgres", "user=postgres password=postgres dbname=messenger sslmode=disable")
	if err != nil {
		log.Fatalln(err)
	}

	// uncomment for setting up db tables
	//db.MustExec(schema)

	r := mux.NewRouter()
	routes := mux.NewRouter()
	r.PathPrefix("/").Handler(negroni.New(
		negroni.NewRecovery(),
		negroni.NewLogger(),
		negroni.Wrap(routes),
	))

	// used to check if server is live
	routes.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pong")
	}).Methods("POST")

	routes.HandleFunc("/signup", NewUser).Methods("POST")
	routes.HandleFunc("/login", Login).Methods("POST")
	routes.HandleFunc("/messages", NewMessage).Methods("POST")
	routes.HandleFunc("/{user}/messages", GetUsersMessages).Methods("GET")
	log.Fatal(http.ListenAndServe(":8080", r))

}