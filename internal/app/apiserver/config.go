package apiserver

import(
	"github.com/c10ver/jwt-auth-golang/internal/app/store"
	"os"
)

type Config struct {
	port string 
	logLevel string 
	store *store.Config
}

func NewConfig() *Config {
	port := ":5000"
	if os.Getenv("PORT") != "" {
		port = ":" + os.Getenv("PORT") 
	} 

	return &Config{
		port: port,
		logLevel: "debug",
		store: store.NewCongif(),
	}
}