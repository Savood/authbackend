package database

import (
	"log"
	"github.com/globalsign/mgo"
	"os"
	"github.com/streadway/amqp"
)

var db *mgo.Database
var mqChannel *amqp.Channel

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

	conn, err := amqp.Dial(os.Getenv("RABBITMQ_URL"))
	if err != nil {
		log.Fatal(err)
	}
	channel, err := conn.Channel()
	if err != nil {
		log.Fatal(err)
	}

	_, err = channel.QueueDeclare(
		"email", // name
		false,   // durable
		false,   // delete when unused
		false,   // exclusive
		false,   // no-wait
		nil,     // arguments
	)
	if err != nil {
		log.Fatal(err)
	}

	mqChannel = channel
}

func GetDatabase() *mgo.Database {
	return db
}

func GetMessageQueue() *amqp.Channel {
	return mqChannel
}
