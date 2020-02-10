package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

/*
create table kv (
	k string,
	v bytea,
	e timestamptz,
	primary key (k)
);
create index kv_e_idx on kv (e);
alter table kv configure zone using gc.ttlseconds = 300;
*/

type CockroachDB struct {
	db *sql.DB
}

func NewCockroachDB(db *sql.DB) *CockroachDB {
	return &CockroachDB{db: db}
}

func (s *CockroachDB) ClearExp() error {
	_, err := s.db.Exec(`delete from kv where e <= now()`)
	return err
}

func (s *CockroachDB) Set(key string, value []byte, exp time.Duration) error {
	expAt := sql.NullTime{}
	if exp > 0 {
		expAt = sql.NullTime{
			Time:  time.Now().Add(exp),
			Valid: true,
		}
	}

	_, err := s.db.Exec(
		`upsert into kv (k, v, e) values ($1, $2, $3)`,
		key,
		value,
		expAt,
	)
	return err
}

func (s *CockroachDB) Get(key string) ([]byte, error) {
	var val []byte
	err := s.db.QueryRow(
		`select v from kv where k = $1 and (e is null or e > $2)`,
		key,
		time.Now(),
	).Scan(&val)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}

func (s *CockroachDB) Del(key string) (bool, error) {
	result, err := s.db.Exec(
		`delete from kv where k = $1 and (e is null or e > $2)`,
		key, time.Now(),
	)
	if err != nil {
		return false, err
	}
	aff, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return aff > 0, nil
}

func (s *CockroachDB) SetExp(key string, exp time.Duration) (bool, error) {
	now := time.Now()

	expAt := sql.NullTime{}
	if exp > 0 {
		expAt = sql.NullTime{
			Time:  now.Add(exp),
			Valid: true,
		}
	}

	result, err := s.db.Exec(
		`update kv set e = $2 where k = $1 and (e is null or e > $3)`,
		key,
		expAt,
		now,
	)
	if err != nil {
		return false, err
	}
	aff, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return aff > 0, nil
}

func (s *CockroachDB) Exp(key string) (time.Duration, bool, error) {
	var exp sql.NullTime
	err := s.db.QueryRow(
		`select e from kv where k = $1 and (e is null or e > $2)`,
		key,
		time.Now(),
	).Scan(&exp)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}

	if !exp.Valid {
		return 0, true, nil
	}

	expIn := time.Until(exp.Time)
	if expIn < 0 {
		return 0, false, nil
	}

	return expIn, true, nil
}

func (s *CockroachDB) Keys(pattern string) ([]string, error) {
	if !strings.Contains(pattern, "*") {
		pattern += "*"
	}

	pattern = "^" + strings.ReplaceAll(pattern, "*", ".*") + "$"

	var r []string
	rows, err := s.db.Query(
		`select k from kv where k ~ $1 and (e is null or e > $2)`,
		pattern,
		time.Now(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var x string
		err := rows.Scan(&x)
		if err != nil {
			return nil, err
		}
		r = append(r, x)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}

	return r, nil
}

func (s *CockroachDB) Scan(cursor int, pattern string, count int) (int, []string, error) {
	if !strings.Contains(pattern, "*") {
		pattern += "*"
	}

	pattern = "^" + strings.ReplaceAll(pattern, "*", ".*") + "$"

	var r []string
	rows, err := s.db.Query(
		`select k from kv where k ~ $1 and (e is null or e > $2) limit $3 offset $4`,
		pattern,
		time.Now(),
		count,
		cursor,
	)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var x string
		err := rows.Scan(&x)
		if err != nil {
			return 0, nil, err
		}
		r = append(r, x)
	}
	if err = rows.Err(); err != nil {
		return 0, nil, err
	}
	if err = rows.Close(); err != nil {
		return 0, nil, err
	}

	cursor += len(r)
	return cursor, r, nil
}
