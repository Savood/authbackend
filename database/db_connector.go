package database

import (
	"log"
	"github.com/globalsign/mgo"
	"os"
)

var db *mgo.Database

func ConnectDatabase() {
	session, err := mgo.Dial(os.Getenv("MONGODB_URL"))
	if err != nil {
		log.Fatal(err)
	}
	db = session.DB(os.Getenv("MONGODB_DB"))

	db.C("users").EnsureIndex(mgo.Index{
		Key:    []string{"email"},
		Unique: true,
	})
	db.C("users").EnsureIndex(mgo.Index{
		Key:    []string{"username"},
		Unique: true,
	})
}

func GetDatabase() *mgo.Database {
	return db
}
