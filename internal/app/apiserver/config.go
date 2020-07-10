package apiserver

import(
	"github.com/c10ver/jwt-auth-golang/internal/app/store"
)

type Config struct {
	port string 
	logLevel string 
	store *store.Config
}

func NewConfig() *Config {
	return &Config{
		port: ":8080",
		logLevel: "debug",
		store: store.NewCongif(),
	}
}