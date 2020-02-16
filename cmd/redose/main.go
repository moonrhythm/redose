package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v7"
	_ "github.com/lib/pq"

	"github.com/moonrhythm/redose"
)

// flags
var (
	port          = flag.Int("p", 6379, "port")
	tlsKey        = flag.String("tls-key", "", "TLS Private Key")
	tlsCrt        = flag.String("tls-crt", "", "TLS Certificate")
	redisAddr     = flag.String("redis-addr", "", "redis address")
	redisPass     = flag.String("redis-pass", "", "redis password")
	redisPoolSize = flag.Int("redis-pool-size", 0, "redis pool size")
	auth          = flag.Bool("auth", false, "enable auth")
	authURI       = flag.String("auth-uri", "", "auth sql uri")
)

func main() {
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	enableTLS := *tlsKey != "" && *tlsCrt != ""

	if *redisAddr == "" {
		log.Fatalf("redis-addr required")
	}
	if *auth && *authURI == "" {
		log.Fatalf("auth uri required")
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:         *redisAddr,
		Password:     *redisPass,
		MaxRetries:   10,
		DialTimeout:  time.Second,
		PoolSize:     *redisPoolSize,
		MinIdleConns: *redisPoolSize,
	})
	defer redisClient.Close()

	srv := redose.Server{
		Addr:        addr,
		RedisClient: redisClient,
		EnableAuth:  *auth,
	}

	if *auth {
		sqlDB, err := sql.Open("postgres", *authURI)
		if err != nil {
			log.Fatalf("can not open sql database; %v", err)
			return
		}
		sqlDB.SetConnMaxLifetime(time.Minute)
		defer sqlDB.Close()

		srv.AuthService = &redose.Auth{
			DB: sqlDB,
		}
	}

	log.Printf("redose server starting at %s", addr)

	var err error
	if enableTLS {
		err = srv.ListenAndServeTLS(*tlsCrt, *tlsKey)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil {
		log.Fatal(err)
	}
}
