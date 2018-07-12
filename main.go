package main

import (
	"git.dhbw.chd.cx/savood/authbackend/database"
	"log"
	"git.dhbw.chd.cx/savood/authbackend/web"
	"net/http"
	"github.com/rs/cors"
)

func main() {
	database.ConnectDatabase()

	router := web.NewRouter()

	corsHandler := cors.New(cors.Options{
		Debug:            false,
		AllowedHeaders:   []string{"*"},
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedMethods:   []string{},
		MaxAge:           1000,
	})

	log.Fatal(http.ListenAndServe(":8080", corsHandler.Handler(router)))
}
