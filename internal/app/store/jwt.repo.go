package store

import(
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"context"
	"strings"
	"errors"
	"time"
	"os"
)

type JWT struct{
	ID primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	GUID string
	Refresh string
}

type TokenPair struct{
	AccessToken string
	RefreshToken string
}

type AccessPayload struct{
	PairId string
	Guid string
	jwt.StandardClaims
}

type RefreshPayload struct{
	ID string
	jwt.StandardClaims
}

// Принимает пару токенов и guid и загружает в бд
func (s *Store) UploadJWT(jwt *JWT) error {
	// Инициализируем коллекцию
	collection := s.db.Database("golang_jwt").Collection("Tokens")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	// Инициализируем документ
	hashRToken, err := hashToken(jwt.Refresh)
	if err != nil {
		return err
	}
	if hashRToken == "" {
		return errors.New("Error hashing tokens")
	}

	jwt.Refresh = hashRToken

	session, err := s.db.StartSession(); 
	if err != nil {
		return err
	}
	if err = session.StartTransaction(); err != nil {
		return err
	}
	if err = mongo.WithSession(ctx, session, func(sc mongo.SessionContext) error {
		result, err := collection.InsertOne(sc, jwt); 
		if err != nil {
			return err
		}
		if result.InsertedID == nil {
			return errors.New("insert failed")
		}
	
		if err = session.CommitTransaction(sc); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	session.EndSession(ctx)
	return nil
}

// Принимает refresh токен и обновляет пару токенов
func (s *Store) RefreshJWT(claim *RefreshPayload, refreshToken string) (*TokenPair, error) {
	// Декларируем коллекцию
	collection := s.db.Database("golang_jwt").Collection("Tokens")
	// Определяем фильтр по id документа
	docId, err := primitive.ObjectIDFromHex(claim.ID)
	if err != nil {
		s.logger.Info("Invalid doc id: ", claim.ID)
		return nil, err
	}

	filter := bson.M{"_id": docId}
	
	// Инизиализируем документ 
	jwt := &JWT{}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	session, err := s.db.StartSession()
	if err != nil {
		return nil, err
	}
	if err = session.StartTransaction(); err != nil {
		return nil, err
	}

	// Инициализируем пару токенов
	var tpair *TokenPair

	if err = mongo.WithSession(ctx, session, func(sc mongo.SessionContext) error {	
		// Ищем пару токенов по значению filter и записываем результат в jwt
		if err := collection.FindOne(ctx, filter).Decode(&jwt); err != nil {
			return errors.New("Invalid refresh token")
		} 

		if err := bcrypt.CompareHashAndPassword([]byte(jwt.Refresh), []byte(refreshToken)); err != nil {
			return errors.New("Invalid refreshToken")
		}


		newId := primitive.NewObjectID()
		newIdString := strings.Replace(strings.Trim(newId.String(), "( \" )"), "ObjectID(\"", "", -1)

		// Создаем новую пару токенов
		tpair, err = CreateTokens(jwt.GUID, newIdString)
		if err != nil {
			return err
		}

		// Хешируем токены
		hashRToken, err := hashToken(tpair.RefreshToken)
		if err != nil {
			return err
		}
		if hashRToken == "" {
			return errors.New("Error hashing tokens")
		}

		jwt = &JWT{
			ID: newId,
			Refresh: hashRToken,
			GUID: jwt.GUID,
		}
	
		// Обновляем документ по значению update
		result, err := collection.DeleteOne(sc, filter); 
		if err != nil {
			return err;
		}
		
		// Если в базе были найдены несколько одинаковых refresh токенов - выдаем ошибку 
		if result.DeletedCount > 1 {
			return errors.New("There are several identical refresh tokens in the database")
		}

		_, err = collection.InsertOne(sc, jwt); 
		if err != nil {
			return err;
		}

		if err = session.CommitTransaction(sc); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return nil, err
	}

	session.EndSession(ctx)

	if tpair == nil {
		return nil, errors.New("Error refresh tokens")
	}

	return tpair, nil
} 

// Принимает refresh токен и удаляет его из бд
func (s *Store) DeleteOneJWT(docId string, accessToken string) error {
	collection := s.db.Database("golang_jwt").Collection("Tokens")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	s.logger.Info("PairId: ", docId)

	// Определяем фильтр по id пары токену
	id, err := primitive.ObjectIDFromHex(docId)
	if err != nil {
		return err
	}
	
	claim, err := DecodeAccessToken(accessToken)
	if err != nil {
		return err
	}

	filter := bson.D{{"_id", id}, {"guid", claim.Guid}}

	session, err := s.db.StartSession()
	if err != nil {
		return err
	}
	if err = session.StartTransaction(); err != nil {
		return err
	}

	if err = mongo.WithSession(ctx, session, func(sc mongo.SessionContext) error {	
		// Удаляем пару токенов из бд
		result, err := collection.DeleteOne(ctx, filter)
		if err != nil {
			return err
		}
		if result.DeletedCount <= 0 {
			return errors.New("Refresh token not found")
		}
		
		return nil
	}); err != nil {
		return err
	}

	
	session.EndSession(ctx)
	return nil
}

// Удаляет все пары токенов по guid, возвращает количество удаленных пар токенов
func (s *Store) DeleteAllJWT(accessToken string) (int64, error) {
	collection := s.db.Database("golang_jwt").Collection("Tokens")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	// Декодируем access токен
	claim, err := DecodeAccessToken(accessToken)
	if err != nil {
		return 0, err
	}

	session, err := s.db.StartSession()
	if err != nil {
		return 0, err
	}
	if err = session.StartTransaction(); err != nil {
		return 0, err
	}

	var deleteCount int64

	if err := mongo.WithSession(ctx, session, func(sc mongo.SessionContext) error {	
		
		// Определяем фильтр по guid
		filter := bson.D{{"guid", claim.Guid}}

		// Удаляем все пары токенов из бд
		result, err := collection.DeleteMany(ctx, filter)
		if err != nil {
			return err
		}
		if result.DeletedCount <= 0 {
			return errors.New("Tokens not found")
		}

		deleteCount = result.DeletedCount 

		return nil
	}); err != nil {
		return 0, err
	}

	
	session.EndSession(ctx)
	return deleteCount, nil
}

// Принимает GUID и возвращает пару токенов
func CreateTokens(guid string, docId string) (*TokenPair, error) {
	AtExpires := time.Now().Add(time.Minute * 15).Unix() // Срок Access токена - 15 минут
	RtExpires := time.Now().Add(time.Hour * 24 * 7).Unix() // Срок Refresh токена - 7 дней

	// Декларируем ключи для подписи с env
	accessSecret := []byte(os.Getenv("ACCESS_KEY"))
	refreshSecret := []byte(os.Getenv("REFRESH_KEY"))

	// Если не найдено одного из ключей
	if len(accessSecret) <= 0 || len(refreshSecret) <= 0 {
		return nil, errors.New("Set refresh and access secret key to .env")
	}
	
	// Декларируем содержимое токенов
	Aclaims := AccessPayload{
		docId,
		guid,
		jwt.StandardClaims{
			ExpiresAt: AtExpires,
		},
	}
	Rclaims := RefreshPayload{
		docId,
		jwt.StandardClaims{
			ExpiresAt: RtExpires,
		},
	}
	atoken := jwt.NewWithClaims(jwt.SigningMethodHS512, Aclaims)
	sat, err := atoken.SignedString(accessSecret)
	
	rtoken := jwt.NewWithClaims(jwt.SigningMethodHS512, Rclaims)
	srt, err := rtoken.SignedString(refreshSecret)
	if err != nil {
	   return nil, err
	}

	tpair := &TokenPair{
		sat,
		srt,
	}

	return tpair, nil
}

// Хеширует токен
func hashToken(token string) (string, error) {
	hashToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashToken), nil
}

// Декодирует access токен
func DecodeAccessToken(tokenString string) (*AccessPayload, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessPayload{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Unexpected signing method")
		}	

        return []byte(os.Getenv("ACCESS_KEY")), nil
    })	
	if err != nil || token == nil {
		return nil, errors.New("Error decoding token")
	}

    if claims, ok := token.Claims.(*AccessPayload); ok && token.Valid {
		return claims, nil
	}
	
	return nil, err
}

// Декодирует refresh токен
func DecodeRefreshToken(tokenString string) (*RefreshPayload, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshPayload{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Unexpected signing method")
		}	

        return []byte(os.Getenv("REFRESH_KEY")), nil
    })	
	if err != nil || token == nil {
		return nil, errors.New("Error decoding token")
	}

    if claims, ok := token.Claims.(*RefreshPayload); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

func (s *Store) VerifyAccessToken(claim *AccessPayload) error {
	collection := s.db.Database("golang_jwt").Collection("Tokens")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	docId, err := primitive.ObjectIDFromHex(claim.PairId)
	if err != nil {
		return err
	}
	
	filter := bson.M{"_id": docId}
    s.logger.Info("docId: ", claim.PairId)
	jwt := &JWT{}
	if err := collection.FindOne(ctx, filter).Decode(&jwt); err != nil {
		s.logger.Error(err)
		return err
	} 
	if len(jwt.Refresh) <= 0 {
		return errors.New("Access token is invalid")
	}

	return nil
}
