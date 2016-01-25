# go-messenger-server
A Golang implementation of a simple messaging server with authentication and encrypted stored passwords.

Uses gorilla/mux for routing, negroni for middleware, PostgeSQL for persistence, jwt for auth, bcrypt for storing passwords.

Must be logged in to use any routes under /api.

Routes that involve a user (e.g. /api/:user/*) will only allow that user to perform the action. 
