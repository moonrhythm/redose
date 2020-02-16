package redose

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"sync"
	"time"
)

/*
create table users (
	username varchar,
	password varchar not null,
	primary key (username)
);
*/

var ErrInvalidCredentials = errors.New("invalid credentials")

// Auth use sql database for retrieve user
type Auth struct {
	DB *sql.DB

	cached sync.Map
}

func (a *Auth) getPasswordWithoutRetry(user string) (password string, err error) {
	err = a.DB.QueryRow(`select password from users where username = $1`, user).Scan(&password)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidCredentials
	}
	return
}

func (a *Auth) getPassword(user string) (password string, err error) {
	pass, ok := a.cached.Load(user)
	if ok {
		return pass.(string), nil
	}

	for i := 0; i < 10; i++ {
		password, err = a.getPasswordWithoutRetry(user)
		if errors.Is(err, ErrInvalidCredentials) {
			return
		}
		if err == nil {
			a.cached.Store(user, password)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	return
}

func (a *Auth) Validate(user, password string) error {
	pass, err := a.getPassword(user)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
		return ErrInvalidCredentials
	}
	return nil
}
