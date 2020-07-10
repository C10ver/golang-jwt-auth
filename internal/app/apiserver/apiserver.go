package apiserver

import (
	"github.com/c10ver/jwt-auth-golang/internal/app/store"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"github.com/golang/gddo/httputil/header"
	"github.com/sirupsen/logrus"
	"github.com/gorilla/mux"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"errors"
	"io"
)

type APIServer struct{
	config *Config
	logger *logrus.Logger
	router *mux.Router
	Store *store.Store
}

type error interface{
	Error() string
}

type malformedRequest struct {
    status int
    msg    string
}

func (mr *malformedRequest) Error() string {
    return mr.msg
}


func New(config *Config) *APIServer {
	return &APIServer{
		config: config,
		logger: logrus.New(),
		router: mux.NewRouter(),
	}
}

// Запускает сервер
func (s *APIServer) Start() error {

	// Настраиваем логгер
	if err := s.configureLogger(); err != nil {
		return err
	}

	// Настраиваем подключение к базе данных
	if err := s.configureStore(); err != nil {
		return err
	}

	// Настраиваем роутер
	s.configureRouter()
	
	
	s.logger.Info("Starting server on "+s.config.port)
	s.Store.Open()
	
	// Слушаем порт указанный в конфиге
	return http.ListenAndServe(s.config.port, s.router)
}

// Настраивает логгер сервера
func (s *APIServer) configureLogger() error {
	level, err := logrus.ParseLevel(s.config.logLevel);
	if err != nil {
		return err
	}
	
	s.logger.SetLevel(level)
	
	return nil
}

// Настраивает подключение к бд
func (s *APIServer) configureStore() error {
	st := store.New(s.config.store)
	s.Store = st
		
	return nil
}

// Настраивает роутер сервера
func (s *APIServer) configureRouter() {
	// Указываем обработчики маршрутов

	// POST /getTokens?guid=...
	// Генерирует и аозвращает пару токенов 
	s.router.Path("/getTokens").Queries("guid", "{guid}").HandlerFunc(s.handleGetTokens()).Methods("POST")

	// PUT /refreshTokens 
	// JSON BODY : { refreshToken string }
	// Обновляет и возвращает пару токенов
	s.router.Path("/refreshTokens").HandlerFunc(s.handleRefreshTokens()).Methods("PUT")

	// DELETE /deleteOneToken?pairId=...
	// Удаляет пару токенов
	s.router.Path("/deleteOneToken").Queries("docId", "{docId}").HandlerFunc(s.checkAccessToken(s.handleDeleteOneToken())).Methods("DELETE")

	// DELETE /deleteAllTokens 
	// Удаляет все токены по guid
	s.router.Path("/deleteAllTokens").HandlerFunc(s.checkAccessToken(s.handleDeleteAllTokens())).Methods("DELETE")
}

// Обрабатывает POST /getTokens 
func (s *APIServer) handleGetTokens() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Инициализируем guid из параметров ссылки
		guid := r.FormValue("guid")
		if len(guid) <= 0 {
			http.Error(w, "guid required", 402)
			return
		}

		// Инициализируем objectId пары
		docId := primitive.NewObjectID()
		s.logger.Info("PairId: ", docId)
		stringId := strings.Replace(strings.Trim(docId.String(), "( \" )"), "ObjectID(\"", "", -1)
		s.logger.Info("PairId: ", stringId)

		// Создаем пару токенов
		tpair, err := store.CreateTokens(guid, stringId)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		
		jwt := &store.JWT{
			ID: docId,
			GUID: guid,
			Refresh: tpair.RefreshToken,
		}

		// Загружаем пару токенов в бд
		if err := s.Store.UploadJWT(jwt); err != nil {
			http.Error(w, "Error uploading token: "+err.Error(), 520)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tpair)
	}
} 

// Обрабатывает PUT /refreshTokens 
func (s *APIServer) handleRefreshTokens() http.HandlerFunc {
	type Req struct{
		RefreshToken string
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &Req{}
		if err := decodeJSONBody(w, r, req); err != nil {
			var mr *malformedRequest
			if errors.As(err, &mr) {
				http.Error(w, mr.msg, mr.status)
			} else {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			return
		}
		if len(req.RefreshToken) <= 0 {
			http.Error(w, "Refresh token is required", 400)
			return
		} 

		s.logger.Info("RefreshToken: "+req.RefreshToken)
		
		claim, err := store.DecodeRefreshToken(req.RefreshToken)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		tpair, err := s.Store.RefreshJWT(claim, req.RefreshToken)
		if err != nil {
			s.logger.Error(err)
			http.Error(w, err.Error(), 400)
			return
		}
		response, err := json.Marshal(tpair)
		if err != nil {
			s.logger.Error(err)
			io.WriteString(w, err.Error())
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	}
}

// Обработчик DELETE /deleteOneToken?docId=...
func (s *APIServer) handleDeleteOneToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Инициализируем pairId из параметров ссылки
		docId := r.FormValue("docId")
		if len(docId) <= 0 {
			http.Error(w, "docId required", 402)
			return
		}

		// Берем access токен из заголовка запроса
		accessToken := strings.Split(r.Header.Get("Authorization"), "Bearer ")[1]
		
		// Удаляем пару токенов ее id 
		if err := s.Store.DeleteOneJWT(docId, accessToken); err != nil {
			status := 404
			if err.Error() != "Refresh token not found"  {
				status = 500
			}
			http.Error(w, err.Error(), status)
			return
		}

		io.WriteString(w, "ok")
	}
}

// Обработчик DELETE /deleteAllTokens
func (s *APIServer) handleDeleteAllTokens() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accessToken := strings.Split(r.Header.Get("Authorization"), "Bearer ")[1]
		result, err := s.Store.DeleteAllJWT(accessToken)
		if err != err {
			http.Error(w, err.Error(), 520)
			return
		}
		io.WriteString(w, "Deleted "+strconv.FormatInt(result, 10)+" token pairs")
	}
}

// Проверяет наличие refresh токена в теле запроса
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	// Проверяем тип контента запроса 
	if r.Header.Get("Content-Type") != "" {
		value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
		if value != "application/json" {
			msg := "Content-Type header is not application/json"
			return &malformedRequest{status: http.StatusUnsupportedMediaType, msg: msg}
		}
	}
	
	// Ограничение на размер запроса в 1мб
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	dec := json.NewDecoder(r.Body)
	
	// Отслеживает незнакомые значения в теле запроса
	dec.DisallowUnknownFields() 

	// Декодируем тело запроса
	err := dec.Decode(&dst)
	if err != nil {
		return &malformedRequest{status: 500, msg: "Error decoding request body"}
	}

	err = dec.Decode(&struct{}{})
	if err != io.EOF {
		msg := "Request body must only contain a single JSON object"
		return &malformedRequest{status: 400, msg: msg}
	}

	return nil
}

// Проверяет валидность access токена в заголовке запроса
func (s *APIServer) checkAccessToken(next http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
	// Достаем токен из заголовка
	accessToken := r.Header.Get("Authorization")
	if len(accessToken) <= 0 || len(strings.Split(accessToken, "Bearer ")) == 1 {
		http.Error(w, "Access token is required", 401)
		return
	}

	accessToken = strings.Split(accessToken, "Bearer ")[1]
	
	s.logger.Info("Access token: 	", accessToken)

	// Если токен не найден
	if len(accessToken) <= 0 {
		http.Error(w, "Bearer token not found", 401)
		return
	} 

	// Декодируем токен
	claim, err := store.DecodeAccessToken(accessToken)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}

	if err := s.Store.VerifyAccessToken(claim); err != nil{
		http.Error(w, "Authorization failed", 401)
		return
	} 
 
    next(w, r)
  }
}