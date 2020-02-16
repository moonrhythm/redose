package redose

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v7"
	"github.com/tidwall/redcon"
)

type session struct {
	User string
}

// Server is the redose server
type Server struct {
	Addr        string
	TLSConfig   *tls.Config
	EnableAuth  bool
	AuthService *Auth
	RedisClient *redis.Client

	mux redcon.Handler
}

func (h *Server) init() {
	mux := redcon.NewServeMux()
	h.mux = mux

	mux.HandleFunc("ping", h.Ping)
	mux.HandleFunc("quit", h.Quit)
	mux.HandleFunc("auth", h.Auth)
	mux.HandleFunc("dbsize", h.DBSize)
	mux.HandleFunc("select", h.Select)
	mux.HandleFunc("info", h.Info)
	mux.HandleFunc("set", h.Set)
	mux.HandleFunc("get", h.Get)
	mux.HandleFunc("mget", h.MGet)
	mux.HandleFunc("type", h.Type)
	mux.HandleFunc("del", h.Del)
	mux.HandleFunc("expire", h.Expire)
	mux.HandleFunc("pexpire", h.PExpire)
	mux.HandleFunc("ttl", h.TTL)
	mux.HandleFunc("pttl", h.PTTL)
	mux.HandleFunc("scan", h.Scan)
}

func (h *Server) ListenAndServe() error {
	h.init()

	return redcon.ListenAndServe(h.Addr, h.mux.ServeRESP, h.acceptCallback, h.closedCallback)
}

func (h *Server) ListenAndServeTLS(certFile, keyFile string) error {
	h.init()

	tlsConfig := h.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}

	return redcon.ListenAndServeTLS(h.Addr, h.mux.ServeRESP, h.acceptCallback, h.closedCallback, tlsConfig)
}

func (h *Server) acceptCallback(conn redcon.Conn) bool {
	conn.SetContext(&session{})
	// log.Printf("accept: %s", conn.RemoteAddr())
	return true
}

func (h *Server) closedCallback(conn redcon.Conn, err error) {
	// log.Printf("closed: %s, err: %v", conn.RemoteAddr(), err)
}

func (h *Server) wrongNumberArgs(conn redcon.Conn, cmd redcon.Command) {
	conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
}

func (h *Server) error(conn redcon.Conn, err error) {
	log.Printf("error %v", err)
	// conn.WriteError("ERR " + err.Error())
	conn.WriteError("ERR Internal Error")
}

func (h *Server) errorString(conn redcon.Conn, err string) {
	conn.WriteError("ERR " + err)
}

func (h *Server) sessionKey(conn redcon.Conn, key string) string {
	if !h.EnableAuth {
		return key
	}

	return conn.Context().(*session).User + ":" + key
}

func (h *Server) sessionKeyLen(conn redcon.Conn) int {
	return len(h.sessionKey(conn, ""))
}

func (h *Server) setSessionKey(conn redcon.Conn, cmd redcon.Command, index int) {
	if len(cmd.Args) < index {
		return
	}
	cmd.Args[index] = []byte(h.sessionKey(conn, string(cmd.Args[index])))
}

func (h *Server) convertCmd(cmd redcon.Command) []interface{} {
	v := make([]interface{}, len(cmd.Args))
	for i := range v {
		v[i] = string(cmd.Args[i])
	}
	return v
}

func (h *Server) checkAuth(conn redcon.Conn) bool {
	if !h.EnableAuth {
		return true
	}

	if conn.Context().(*session).User == "" {
		conn.WriteError("NOAUTH Authentication required.")
		return false
	}
	return true
}

func (h *Server) Ping(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) > 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	pong := "PONG"
	if len(cmd.Args) == 2 {
		pong = string(cmd.Args[1])
	}

	conn.WriteString(pong)
}

func (h *Server) Quit(conn redcon.Conn, cmd redcon.Command) {
	conn.WriteString("OK")
	conn.Close()
}

func (h *Server) Auth(conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	if !h.EnableAuth {
		h.errorString(conn, "Client sent AUTH, but no password is set")
		return
	}

	sess := conn.Context().(*session)
	sess.User = ""

	userPass := strings.SplitN(string(cmd.Args[1]), ":", 2)
	if len(userPass) != 2 {
		h.errorString(conn, "invalid password")
		return
	}

	err := h.AuthService.Validate(userPass[0], userPass[1])
	if errors.Is(err, ErrInvalidCredentials) {
		h.errorString(conn, "invalid password")
		return
	}
	if err != nil {
		h.error(conn, err)
		return
	}

	sess.User = userPass[0]
	conn.WriteString("OK")
}

func (h *Server) DBSize(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) != 1 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	conn.WriteInt(1)
}

func (h *Server) Select(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) != 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	db, err := strconv.Atoi(string(cmd.Args[1]))
	if err != nil {
		h.errorString(conn, "value is not an integer or out of range")
		return
	}
	if db != 0 {
		h.errorString(conn, "DB index is out of range")
		return
	}

	conn.WriteString("OK")
}

func (h *Server) Info(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) > 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	section := ""
	if len(cmd.Args) == 2 {
		section = strings.ToLower(string(cmd.Args[1]))
	}

	var buf strings.Builder

	endSection := func() {}

	switch section {
	default:
		goto sectionEnd
	case "":
		endSection = func() {
			fmt.Fprintf(&buf, "\r\n")
		}
	case "cluster":
		goto sectionCluster
	case "keyspace":
		goto sectionKeyspace
	}

sectionCluster:
	fmt.Fprintf(&buf, "# Cluster\r\n")
	fmt.Fprintf(&buf, "cluster_enabled:0\r\n")
	endSection()

sectionKeyspace:
	fmt.Fprintf(&buf, "# Keyspace\r\n")
	fmt.Fprintf(&buf, "db0:keys=0,expires=0,avg_ttl=0\r\n")

sectionEnd:
	conn.WriteBulkString(buf.String())
}

func (h *Server) Set(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	// SET key value [EX seconds|PX milliseconds] [NX|XX] [KEEPTTL]
	if len(cmd.Args) < 3 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	h.setSessionKey(conn, cmd, 1)
	c := redis.NewStringCmd(h.convertCmd(cmd)...)
	h.RedisClient.Process(c)

	val, err := c.Result()
	if err != nil {
		h.error(conn, err)
		return
	}
	conn.WriteString(val)
}

func (h *Server) Get(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) != 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	key := h.sessionKey(conn, string(cmd.Args[1]))
	val, err := h.RedisClient.Get(key).Result()
	if err == redis.Nil {
		conn.WriteNull()
		return
	}
	if err != nil {
		h.error(conn, err)
		return
	}
	conn.WriteBulkString(val)
}

func (h *Server) MGet(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) < 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	keys := make([]string, 0, len(cmd.Args)-1)
	for _, key := range cmd.Args[1:] {
		k := h.sessionKey(conn, string(key))
		keys = append(keys, k)
	}

	val, err := h.RedisClient.MGet(keys...).Result()
	if err != nil {
		h.error(conn, err)
		return
	}

	conn.WriteArray(len(cmd.Args) - 1)
	for _, v := range val {
		switch v := v.(type) {
		case string:
			conn.WriteBulkString(v)
		case []byte:
			conn.WriteBulk(v)
		default:
			conn.WriteNull()
		}
	}
}

func (h *Server) Type(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) != 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	key := h.sessionKey(conn, string(cmd.Args[1]))

	val, err := h.RedisClient.Type(key).Result()
	if err == redis.Nil {
		conn.WriteString("none")
		return
	}
	if err != nil {
		h.error(conn, err)
		return
	}

	conn.WriteString(val)
}

func (h *Server) Del(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) < 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	keys := make([]string, 0, len(cmd.Args)-1)
	for _, key := range cmd.Args[1:] {
		k := h.sessionKey(conn, string(key))
		keys = append(keys, k)
	}

	cnt, err := h.RedisClient.Del(keys...).Result()
	if err != nil {
		h.error(conn, err)
		return
	}
	conn.WriteInt64(cnt)
}

func (h *Server) Expire(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) != 3 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	key := h.sessionKey(conn, string(cmd.Args[1]))

	second, err := strconv.ParseInt(string(cmd.Args[2]), 10, 64)
	if err != nil {
		h.errorString(conn, "value is not an integer or out of range")
		return
	}

	expIn := time.Duration(second) * time.Second
	ok, err := h.RedisClient.Expire(key, expIn).Result()
	if err != nil {
		h.error(conn, err)
		return
	}

	if !ok {
		conn.WriteInt(0)
		return
	}

	conn.WriteInt(1)
}

func (h *Server) PExpire(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) != 3 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	key := h.sessionKey(conn, string(cmd.Args[1]))
	millisecond, err := strconv.ParseInt(string(cmd.Args[2]), 10, 64)
	if err != nil {
		h.errorString(conn, "value is not an integer or out of range")
		return
	}

	expIn := time.Duration(millisecond) * time.Millisecond
	ok, err := h.RedisClient.PExpire(key, expIn).Result()
	if err != nil {
		h.error(conn, err)
		return
	}

	if !ok {
		conn.WriteInt(0)
		return
	}

	conn.WriteInt(1)
}

func (h *Server) TTL(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) != 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	key := h.sessionKey(conn, string(cmd.Args[1]))

	c := redis.NewIntCmd("ttl", key)
	h.RedisClient.Process(c)

	val, err := c.Result()
	if err != nil {
		h.error(conn, err)
		return
	}
	conn.WriteInt64(val)
}

func (h *Server) PTTL(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) != 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	key := h.sessionKey(conn, string(cmd.Args[1]))

	c := redis.NewIntCmd("pttl", key)
	h.RedisClient.Process(c)

	val, err := c.Result()
	if err != nil {
		h.error(conn, err)
		return
	}
	conn.WriteInt64(val)
}

func (h *Server) Scan(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	switch len(cmd.Args) {
	default:
		h.wrongNumberArgs(conn, cmd)
		return
	case 2:
	case 4:
	case 6:
	}

	cursor, err := strconv.ParseUint(string(cmd.Args[1]), 10, 64)
	if err != nil {
		h.errorString(conn, "value is not an integer or out of range")
		return
	}

	pattern, _ := getParam(cmd.Args, "match")
	pattern = h.sessionKey(conn, pattern)

	count, ok, err := getParamInt64(cmd.Args, "count")
	if err != nil {
		h.errorString(conn, "value is not an integer or out of range")
		return
	}
	if !ok {
		count = 10
	}

	keys, cursor, err := h.RedisClient.Scan(cursor, pattern, count).Result()
	if err != nil {
		h.error(conn, err)
		return
	}

	prefix := h.sessionKeyLen(conn)

	conn.WriteArray(2)
	conn.WriteBulkString(strconv.FormatUint(cursor, 10))

	conn.WriteArray(len(keys))
	for _, k := range keys {
		conn.WriteBulkString(k[prefix:])
	}
}

func getParam(args [][]byte, name string) (string, bool) {
	l := len(args)
	for i := 0; i+1 < l; i += 2 {
		if strings.ToLower(string(args[i])) == name {
			return string(args[i+1]), true
		}
	}
	return "", false
}

func getParamInt64(args [][]byte, name string) (int64, bool, error) {
	p, ok := getParam(args, name)
	if !ok {
		return 0, false, nil
	}
	i, err := strconv.ParseInt(p, 10, 64)
	return i, true, err
}
