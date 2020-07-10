package main

import (
	"github.com/c10ver/jwt-auth-golang/internal/app/apiserver"
	"log"
	"os"
)

func main() {
	// Устанавливаем переменные среды
	os.Setenv("DATABASE_URI", "mongodb+srv://admin:supersecret@cluster0.g3l1s.mongodb.net/golang_jwt")
	os.Setenv("ACCESS_KEY", "supersecret")
	os.Setenv("REFRESH_KEY", "superpupersecret")
	
	// Конфигурируем сервер
	config := apiserver.NewConfig()
	s := apiserver.New(config)

	// Запускаем сервер
	if err := s.Start(); err != nil {
		log.Fatal(err)
	}
}