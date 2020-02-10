package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/moonrhythm/redose"
	"github.com/moonrhythm/redose/store"
)

// flags
var (
	port      = flag.Int("p", 6379, "port")
	tlsKey    = flag.String("tls-key", "", "TLS Private Key")
	tlsCrt    = flag.String("tls-crt", "", "TLS Certificate")
	storeMode = flag.String("s", "mem", "storage mode")
	auth      = flag.Bool("auth", false, "enable auth")
)

func main() {
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	enableTLS := *tlsKey != "" && *tlsCrt != ""

	log.Printf("redose server starting at %s", addr)

	// normalize store mode
	storeArgs := strings.SplitN(*storeMode, ",", 2)
	if len(storeArgs) == 0 {
		storeArgs = []string{""}
	}

	var s redose.Storage
	switch storeArgs[0] {
	default:
		log.Fatalf("invalid store mode")
	case "mem":
		s = store.NewMemory()
	case "crdb":
		db, err := sql.Open("postgres", storeArgs[1])
		if err != nil {
			log.Fatalf("can not open crdb; %v", err)
		}
		db.SetMaxIdleConns(200)
		db.SetConnMaxLifetime(time.Hour)
		s = store.NewCockroachDB(db)
	}

	go func() {
		time.Sleep(time.Minute)

		for {
			log.Printf("store: clear exp")
			s.ClearExp()
			time.Sleep(10 * time.Minute)
		}
	}()

	log.Printf("using %s storage mode", storeArgs[0])

	srv := redose.Server{
		Addr:       addr,
		Store:      s,
		EnableAuth: *auth,
	}

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
