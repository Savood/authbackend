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
	"errors"
	"io/ioutil"
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

type AccountUpdate struct {
	EMail    *string `json:"email"`
	Password *string `json:"password"`
}

func AuthorizeRequest(w http.ResponseWriter, r *http.Request) (*services.User, error) {
	key := strings.Split(r.Header.Get("Authorization"), " ")
	if len(key) != 2 {
		w.WriteHeader(http.StatusInternalServerError)
		b, _ := json.Marshal(RegisterResponse{
			Success: false,
		})
		w.Write(b)
		return nil, errors.New("erroohr")
	}

	token, err := jwt.Parse(key[1], func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET_JWT")), nil
	})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		b, _ := json.Marshal(RegisterResponse{
			Success: false,
		})
		w.Write(b)
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		u, e := services.FetchUserById(bson.ObjectIdHex(claims["userid"].(string)))
		if e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			b, _ := json.Marshal(RegisterResponse{
				Success: false,
				Error:   "user could not be found",
			})
			w.Write(b)
			return nil, errors.New("erroohr")
		}

		if !u.Enabled {
			w.WriteHeader(http.StatusInternalServerError)
			b, _ := json.Marshal(RegisterResponse{
				Success: false,
				Error:   "user not verified",
			})
			w.Write(b)
			return nil, errors.New("erroohr")
		}

		return &u, nil
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		b, _ := json.Marshal(RegisterResponse{
			Success: false,
		})
		w.Write(b)
		return nil, errors.New("erroohr")
	}
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
		"userid":   u.ID,
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

	e = u.SendConfirmMail()
	if e != nil {
		fmt.Println(e)
	}

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

func ChangeMailEndPoint(w http.ResponseWriter, r *http.Request) {
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
		if userid, ok := claims["userid"]; ok {
			if email, ok := claims["email"]; ok {
				u, e := services.FetchUserById(bson.ObjectIdHex(userid.(string)))
				if e != nil {
					w.WriteHeader(http.StatusNotFound)
					w.Write([]byte("The user could not be found"))
					return
				}

				if !u.Enabled {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Not verified"))
					return
				}

				if strings.ToLower(u.EMail) == strings.ToLower(email.(string)) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("This has already been verified"))
					return
				}

				u.EMail = email.(string)
				services.SaveUser(u)

				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Your email has been verified successfully"))
				return
			}
		}
	} else {
		fmt.Println(err)
	}

	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("Something went wrong"))
}

func DeleteAccountEndPoint(w http.ResponseWriter, r *http.Request) {
	user, err := AuthorizeRequest(w, r)
	if err != nil {
		return
	}

	err = user.DeleteUser()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User has been removed"))
}

func DeleteSessionsEndPoint(w http.ResponseWriter, r *http.Request) {
	user, err := AuthorizeRequest(w, r)
	if err != nil {
		return
	}

	err = user.DeleteSessions()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("All sessions have been removed"))
}

func ForgotPasswordEndPoint(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")

	user, err := services.FetchUserByEmail(email)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		b, _ := json.Marshal(ErrorResponse{
			Error: "user could not be found",
		})
		w.Write(b)
		return
	}

	w.WriteHeader(http.StatusOK)
	user.SendForgotMail()
	b, _ := json.Marshal(RegisterResponse{
		Success: true,
	})
	w.Write(b)
}

func ResetPasswordEndPoint(w http.ResponseWriter, r *http.Request) {
	// Implement!
}

func ResetPasswordPostEndPoint(w http.ResponseWriter, r *http.Request) {
	// Implement!
}

func UpdateAccountEndPoint(w http.ResponseWriter, r *http.Request) {
	user, err := AuthorizeRequest(w, r)
	if err != nil {
		return
	}

	bytes, e := ioutil.ReadAll(r.Body)
	if e != nil {
		w.WriteHeader(http.StatusInternalServerError)
		b, _ := json.Marshal(RegisterResponse{
			Success: false,
		})
		w.Write(b)
		return
	}

	accountUpdate := &AccountUpdate{}
	json.Unmarshal(bytes, accountUpdate)

	if accountUpdate.EMail != nil {
		if strings.ToLower(user.EMail) == strings.ToLower(*accountUpdate.EMail) {
			w.WriteHeader(http.StatusBadRequest)
			b, _ := json.Marshal(RegisterResponse{
				Success: false,
				Error:   "same email",
			})
			w.Write(b)
			return
		}
		user.SendChangeConfirmMail(*accountUpdate.EMail)
	}

	if accountUpdate.Password != nil {
		hashedPassword, e := bcrypt.GenerateFromPassword([]byte(*accountUpdate.Password), 10)
		if e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			b, _ := json.Marshal(RegisterResponse{
				Success: false,
			})
			w.Write(b)
			return
		}
		user.Password = base64.StdEncoding.EncodeToString(hashedPassword)
		user.SaveUser()
	}

	w.WriteHeader(http.StatusOK)
	b, _ := json.Marshal(RegisterResponse{
		Success: true,
	})
	w.Write(b)
}

func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/oauth2/token", TokenEndPoint).Methods("POST")
	router.HandleFunc("/register", RegisterEndPoint).Methods("POST")
	router.HandleFunc("/confirm", ConfirmEndPoint).Methods("GET")
	router.HandleFunc("/changemail", ChangeMailEndPoint).Methods("GET")

	router.HandleFunc("/account", UpdateAccountEndPoint).Methods("PATCH")

	router.HandleFunc("/account", DeleteAccountEndPoint).Methods("DELETE")
	router.HandleFunc("/sessions", DeleteSessionsEndPoint).Methods("DELETE")

	router.HandleFunc("/forgot", ForgotPasswordEndPoint).Methods("POST")

	router.HandleFunc("/reset", ResetPasswordEndPoint).Methods("GET")
	router.HandleFunc("/reset", ResetPasswordPostEndPoint).Methods("POST")

	return router
}
