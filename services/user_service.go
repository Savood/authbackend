package services

import (
	"github.com/globalsign/mgo/bson"
	"git.dhbw.chd.cx/savood/authbackend/database"
	"crypto/rand"
	"time"
	"encoding/json"
	"github.com/streadway/amqp"
	"os"
	"github.com/dgrijalva/jwt-go"
	"log"
)

type User struct {
	ID       bson.ObjectId `bson:"_id" json:"id"`
	EMail    string        `bson:"email" json:"email"`
	Password string        `bson:"password" json:"password"`
	Enabled  bool          `bson:"enabled" json:"enabled"`
}

type Session struct {
	ID           bson.ObjectId       `bson:"_id" json:"id"`
	UserID       bson.ObjectId       `bson:"user_id" json:"user_id"`
	RefreshToken string              `bson:"refresh_token" json:"refresh_token"`
	Created      bson.MongoTimestamp `bson:"created" json:"created"`
}

type EMail struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes), nil
}

func FetchUserByEmail(email string) (User, error) {
	var user User
	err := database.GetDatabase().C("users").Find(bson.M{"email": email}).One(&user)
	return user, err
}

func FetchUserById(id bson.ObjectId) (User, error) {
	var user User
	err := database.GetDatabase().C("users").FindId(id).One(&user)
	return user, err
}

func (session *Session) FetchUser() (User, error) {
	var user User
	err := database.GetDatabase().C("users").FindId(session.UserID).One(&user)
	return user, err
}

func SaveUser(user User) error {
	_, err := database.GetDatabase().C("users").UpsertId(user.ID, user)
	return err
}

func (user *User) SaveUser() error {
	_, err := database.GetDatabase().C("users").UpsertId(user.ID, user)
	return err
}

func DeleteAllSessions(user User) error {
	_, err := database.GetDatabase().C("sessions").RemoveAll(bson.M{"user_id": user.ID})
	return err
}

func CreateSession(user User) (*Session, error) {
	token, err := GenerateRandomString(80)
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:           bson.NewObjectId(),
		RefreshToken: token,
		UserID:       user.ID,
		Created:      bson.MongoTimestamp(time.Now().Unix() << 32),
	}

	err = database.GetDatabase().C("sessions").Insert(session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func FetchSessionByRefreshToken(refreshToken string) (Session, error) {
	var session Session
	err := database.GetDatabase().C("sessions").Find(bson.M{"refresh_token": refreshToken}).One(&session)
	return session, err
}

func (email *EMail) SendMail() (error) {
	bb, e := json.Marshal(email)
	if e != nil {
		return e
	}

	e = database.GetMessageQueue().Publish(
		"",      // exchange
		"email", // routing key
		false,   // mandatory
		false,   // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(bb),
		})
	return e
}

func (user *User) DeleteSessions() (error) {
	_, err := database.GetDatabase().C("sessions").RemoveAll(bson.M{"user_id": user.ID})
	return err
}

func (user *User) DeleteUser() (error) {
	err := database.GetDatabase().C("users").RemoveId(user.ID)
	return err
}

func (user *User) SendChangeConfirmMail(newemail string) (error) {
	emailToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userid": user.ID.Hex(),
		"email":  newemail,
		"exp":    time.Now().Add(60 * time.Minute).Unix(),
	})

	emailTokenString, e := emailToken.SignedString([]byte(os.Getenv("SECRET_EMAIL")))
	if e != nil {
		log.Println(e)
		return e
	}

	email := EMail{
		Subject: "Bestätige deine neue Savood E-Mail!",
		Text:    "Bitte bestätige deine neue Savood E-Mail: " + os.Getenv("EXTERNAL_BASE") + "/changemail?key=" + emailTokenString,
		To:      newemail,
	}
	return email.SendMail()
}

func (user *User) SendConfirmMail() (error) {
	emailToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userid": user.ID.Hex(),
		"exp":    time.Now().Add(60 * time.Minute).Unix(),
	})

	emailTokenString, e := emailToken.SignedString([]byte(os.Getenv("SECRET_EMAIL")))
	if e != nil {
		log.Println(e)
		return e
	}

	email := EMail{
		Subject: "Bestätige deinen Savood Account!",
		Text:    "Bitte bestätige deinen Account: " + os.Getenv("EXTERNAL_BASE") + "/confirm?key=" + emailTokenString,
		To:      user.EMail,
	}
	return email.SendMail()
}

func (user *User) SendForgotMail() (error) {
	emailToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userid": user.ID.Hex(),
		"exp":    time.Now().Add(60 * time.Minute).Unix(),
	})

	emailTokenString, e := emailToken.SignedString([]byte(os.Getenv("SECRET_EMAIL")))
	if e != nil {
		log.Println(e)
		return e
	}

	email := EMail{
		Subject: "Savood: Password vergessen",
		Text:    "Jemand hat ein neues Passwort angefordert. Klicke diesen Link, falls du es ändern möchtest: " + os.Getenv("EXTERNAL_BASE") + "/reset?key=" + emailTokenString,
		To:      user.EMail,
	}
	return email.SendMail()
}
