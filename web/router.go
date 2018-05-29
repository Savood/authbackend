package web

import (
	"github.com/gorilla/mux"
	"net/http"
	"git.dhbw.chd.cx/savood/authbackend/services"
	"golang.org/x/crypto/bcrypt"
	"github.com/dgrijalva/jwt-go"
	"time"
	"github.com/globalsign/mgo/bson"
	"encoding/base64"
	"fmt"
	"encoding/json"
	"strings"
	"os"
)

type ErrorResponse struct {
	Error string `json:"error"`
}

type TokenResponse struct {
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
}

type RegisterResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func TokenEndPoint(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	grantType := r.FormValue("grant_type")

	var u *services.User = nil
	var s *services.Session = nil

	if grantType == "password" {
		user, err := services.FetchUserByUsername(username)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			b, _ := json.Marshal(ErrorResponse{
				Error: "user could not be found",
			})
			w.Write(b)
			return
		}

		hashedPassword, err := base64.StdEncoding.DecodeString(user.Password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			b, _ := json.Marshal(ErrorResponse{
				Error: "internal server error",
			})
			w.Write(b)
			return
		}

		err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			b, _ := json.Marshal(ErrorResponse{
				Error: "wrong password",
			})
			w.Write(b)
			return
		}

		if !user.Enabled {
			w.WriteHeader(http.StatusUnauthorized)
			b, _ := json.Marshal(ErrorResponse{
				Error: "user is not enabled",
			})
			w.Write(b)
			return
		}

		session, err := services.CreateSession(user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			b, _ := json.Marshal(ErrorResponse{
				Error: "internal server error",
			})
			w.Write(b)
			return
		}

		u = &user
		s = session
	} else if grantType == "refresh_token" {
		refreshToken := r.FormValue("refresh_token")
		session, e := services.FetchSessionByRefreshToken(refreshToken)
		if e != nil {
			w.WriteHeader(http.StatusNotFound)
			b, _ := json.Marshal(ErrorResponse{
				Error: "wrong refresh_token",
			})
			w.Write(b)
			return
		}

		user, e := session.FetchUser()
		if e != nil {
			w.WriteHeader(http.StatusNotFound)
			b, _ := json.Marshal(ErrorResponse{
				Error: "user could not be found",
			})
			w.Write(b)
			return
		}
		u = &user
		s = &session
	} else {
		w.WriteHeader(http.StatusNotFound)
		b, _ := json.Marshal(ErrorResponse{
			Error: "wrong grant_type",
		})
		w.Write(b)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": u.Username,
		"email":    u.EMail,
		"exp":      time.Now().Add(20 * time.Minute).Unix(),
	})

	tokenString, e := token.SignedString([]byte(os.Getenv("SECRET_JWT")))
	if e != nil {
		w.WriteHeader(http.StatusInternalServerError)
		b, _ := json.Marshal(ErrorResponse{
			Error: "internal server error",
		})
		w.Write(b)
		return
	}
	b, _ := json.Marshal(TokenResponse{
		RefreshToken: s.RefreshToken,
		IdToken:      tokenString,
	})
	w.Write(b)
}

func RegisterEndPoint(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	username := r.FormValue("username")
	password := r.FormValue("password")

	hashedPassword, e := bcrypt.GenerateFromPassword([]byte(password), 10)
	if e != nil {
		w.WriteHeader(http.StatusInternalServerError)
		b, _ := json.Marshal(RegisterResponse{
			Success: false,
		})
		w.Write(b)
		return
	}

	u := services.User{
		ID:       bson.NewObjectId(),
		EMail:    email,
		Username: username,
		Password: base64.StdEncoding.EncodeToString(hashedPassword),
	}

	e = services.SaveUser(u)
	if e != nil {
		if strings.Contains(e.Error(), "duplicate key error") {
			w.WriteHeader(http.StatusOK)
			b, _ := json.Marshal(RegisterResponse{
				Success: false,
				Error:   "the username or email are already in use",
			})
			w.Write(b)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		b, _ := json.Marshal(RegisterResponse{
			Success: false,
		})
		w.Write(b)
		return
	}

	u.SendMail()

	w.WriteHeader(http.StatusOK)
	b, _ := json.Marshal(RegisterResponse{
		Success: true,
	})
	w.Write(b)
}

func ConfirmEndPoint(w http.ResponseWriter, r *http.Request) {
	key, ok := r.URL.Query()["key"]
	if !ok || len(key) < 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(key[0], func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET_EMAIL")), nil
	})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Something went wrong"))
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		u, e := services.FetchUserById(bson.ObjectIdHex(claims["userid"].(string)))
		if e != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("The user could not be found"))
			return
		}

		if u.Enabled {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Already verified"))
			return
		}

		u.Enabled = true
		services.SaveUser(u)
	} else {
		fmt.Println(err)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Your account has been verified successfully"))
}

func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/oauth2/token", TokenEndPoint).Methods("POST")
	router.HandleFunc("/register", RegisterEndPoint).Methods("POST")
	router.HandleFunc("/confirm", ConfirmEndPoint).Methods("GET")

	return router
}
