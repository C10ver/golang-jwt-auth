package store

import(
	"os"
)

type Config struct {
	databaseURL string
}

func NewCongif() *Config {
	return &Config{
		databaseURL: os.Getenv("DATABASE_URI"),
	}
}