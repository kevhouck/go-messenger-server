package main
import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"encoding/json"
	"net/http"
	"github.com/gorilla/mux"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"time"
)

func Signup(w http.ResponseWriter, r *http.Request) {
	var userJSON User
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&userJSON)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	username := userJSON.Username
	password := userJSON.Password
	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	passwordBytes := []byte(password)
	hashedPassword, err := bcrypt.GenerateFromPassword(passwordBytes, 12)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	newUserSQL := `INSERT INTO users (username, hashed_password) VALUES ($1, $2)`
	_, err = db.Exec(newUserSQL, username, hashedPassword)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, "new user created")
}

type TokenJSON struct {
	Jwt string `json:"jwt"`
}

func Login(w http.ResponseWriter, r *http.Request) {
	var userJSON User
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&userJSON)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	username := userJSON.Username
	password := userJSON.Password
	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	var dbuser DBUser
	userSQL := `SELECT * from users WHERE username=$1`
	err = db.Get(&dbuser, userSQL, username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(dbuser.HashedPassword), []byte(password))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["username"] = dbuser.Username
	exp := time.Now().Add(time.Hour * 2).Unix()
	token.Claims["exp"] = exp
	tokenString, err := token.SignedString([]byte(jwtSecret))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	encoder := json.NewEncoder(w)
	var tokenJSON TokenJSON
	tokenJSON.Jwt = tokenString
	err = encoder.Encode(&tokenJSON)
	if err != nil {
		fmt.Println(err)
	}
}

func NewMessage(w http.ResponseWriter, r *http.Request) {
	var messageJSON Message
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&messageJSON)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token := context.Get(r, "jwt_user")
	claims := token.(*jwt.Token).Claims
	requestUsername := claims["username"]

	username_to := messageJSON.UsernameTo
	username_from := messageJSON.UsernameFrom
	content := messageJSON.Content

	if requestUsername != username_from  {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "user not authorized to send this message as this user")
		return
	}

	var userTo DBUser
	userSQL := `SELECT * from users WHERE username=$1`
	err = db.Get(&userTo, userSQL, username_to)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "destination user does not exist")
		return
	}

	newMessageSQL := `
			INSERT INTO messages (user_to, user_from, content) VALUES
			( (SELECT user_id from users WHERE username=$1) ,
			  (SELECT user_id from users WHERE username=$2) ,
			  $3)`
	_, err = db.Exec(newMessageSQL, username_to, username_from, content)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, "new message sent")
}

func GetUsersMessages(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["user"]

	token := context.Get(r, "jwt_user")
	claims := token.(*jwt.Token).Claims
	requestUsername := claims["username"]

	if requestUsername != username  {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "user not authorized to see this user's messages")
		return
	}

	userSQL := `
		SELECT users_to.username AS username_to, users_from.username AS username_from, messagesToUser.content from (
			SELECT * from messages WHERE user_to =
				( SELECT user_id from users WHERE username=$1 )
		) AS messagesToUser
		JOIN users users_to ON messagesToUser.user_to=users_to.user_id
		JOIN users users_from ON messagesToUser.user_from=users_from.user_id`

	messages := []Message{}

	err := db.Select(&messages, userSQL, username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	encoder := json.NewEncoder(w)
	encoder.Encode(&messages)
}