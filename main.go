package main

import (
	"git.dhbw.chd.cx/savood/authbackend/database"
	"log"
	"git.dhbw.chd.cx/savood/authbackend/web"
	"net/http"
)

func main() {
	database.ConnectDatabase()

	router := web.NewRouter()

	log.Fatal(http.ListenAndServe(":8080", router))
}
