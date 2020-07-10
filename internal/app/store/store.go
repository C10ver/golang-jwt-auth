package store

import (
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo"
	"github.com/sirupsen/logrus"
	"context"
	"time"
)

type Store struct{
	config *Config
	logger *logrus.Logger
	db *mongo.Client
}

func New(config *Config) *Store {
	return &Store{
		config: config,
		logger: logrus.New(),
	}
}

func (s *Store) Open() error {
	client, err := mongo.NewClient(options.Client().ApplyURI(s.config.databaseURL))
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.db = client
	
	if err = client.Connect(ctx); err != nil {
		return err
	}	
	
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return err
	}
	s.logger.Info("Connected with mongodb")


	return nil
}

func (s *Store) Close() error {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	s.db.Disconnect(ctx)

	return nil
}
