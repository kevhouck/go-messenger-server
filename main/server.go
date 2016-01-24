package main

import (
	"github.com/jmoiron/sqlx"
	_"github.com/lib/pq"
	"github.com/gorilla/mux"
	"net/http"
	"fmt"
	"log"
	"github.com/codegangsta/negroni"
	"github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"time"
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
	authBase := mux.NewRouter()
	apiBase := mux.NewRouter()
	auth := authBase.PathPrefix("/auth").Subrouter()
	api := apiBase.PathPrefix("/api").Subrouter()

	r.PathPrefix("/auth").Handler(negroni.New(
		negroni.NewRecovery(),
		negroni.NewLogger(),
		negroni.Wrap(authBase),
	))

	// must be authenticated for use api routes
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(toekn *jwt.Token) (interface{}, error) {
			return []byte("secret"), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
		UserProperty: "jwt_user",
	})
	r.PathPrefix("/api").Handler(negroni.New(
		negroni.NewRecovery(),
		negroni.NewLogger(),
		negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.HandlerFunc(CheckForJWTExpiration),
		negroni.Wrap(apiBase),
	))

	// used to check if server is live
	auth.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pong")
	}).Methods("POST")

	auth.Path("/signup").HandlerFunc(NewUser).Methods("POST")
	auth.Path("/login").HandlerFunc(Login).Methods("POST")

	api.Path("/messages").HandlerFunc(NewMessage).Methods("POST")
	api.HandleFunc("/{user}/messages", GetUsersMessages).Methods("GET")
	log.Fatal(http.ListenAndServe(":8080", r))

}

func CheckForJWTExpiration(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	token := context.Get(r, "jwt_user")
	claims := token.(*jwt.Token).Claims
	exp := claims["exp"]
	// cast to float, for some reason this is the only type it will cast to
	// even though the claim is actually added as an int64, very weird.
	// the resolution of the time since epoch is maintained, however
	expTimeFloat, ok := exp.(float64)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	expTime := time.Unix(int64(expTimeFloat), 0)
	fmt.Println(expTime.Unix())
	if time.Now().After(expTime) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	next(w, r)
}