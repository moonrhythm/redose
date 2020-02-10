package redose

import (
	"crypto/tls"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/redcon"
	"golang.org/x/crypto/bcrypt"
)

type Storage interface {
	ClearExp() error
	Set(key string, value []byte, exp time.Duration) error
	Get(key string) ([]byte, error)
	Del(key string) (bool, error)
	SetExp(key string, exp time.Duration) (bool, error)
	Exp(key string) (time.Duration, bool, error)
	Keys(pattern string) ([]string, error)
	Scan(cursor int, pattern string, count int) (int, []string, error)
}

type session struct {
	User string
}

// Server is the redose server
type Server struct {
	Addr       string
	TLSConfig  *tls.Config
	EnableAuth bool
	Store      Storage

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
	mux.HandleFunc("keys", h.Keys)
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

	hpass, err := h.Store.Get("_auth:" + userPass[0])
	if err != nil {
		h.error(conn, err)
		return
	}

	err = bcrypt.CompareHashAndPassword(hpass, []byte(userPass[1]))
	if err != nil {
		h.errorString(conn, "invalid password")
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

	if len(cmd.Args) != 3 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	key := h.sessionKey(conn, string(cmd.Args[1]))

	err := h.Store.Set(key, cmd.Args[2], 0)
	if err != nil {
		h.error(conn, err)
		return
	}
	conn.WriteString("OK")
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

	val, err := h.Store.Get(key)
	if err != nil {
		h.error(conn, err)
		return
	}

	if val == nil {
		conn.WriteNull()
		return
	}

	conn.WriteBulk(val)
}

func (h *Server) MGet(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) < 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	conn.WriteArray(len(cmd.Args) - 1)

	for _, key := range cmd.Args[1:] {
		k := h.sessionKey(conn, string(key))
		val, err := h.Store.Get(k)
		if err != nil {
			h.error(conn, err)
		}
		if val == nil {
			conn.WriteNull()
			return
		}
		conn.WriteBulk(val)
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

	val, err := h.Store.Get(key)
	if err != nil {
		h.error(conn, err)
		return
	}

	if val == nil {
		conn.WriteString("none")
		return
	}

	conn.WriteString("string")
}

func (h *Server) Del(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) < 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	var cnt int
	for _, key := range cmd.Args[1:] {
		k := h.sessionKey(conn, string(key))
		ok, err := h.Store.Del(k)
		if err != nil {
			h.error(conn, err)
			return
		}
		if ok {
			cnt++
		}
	}

	conn.WriteInt(cnt)
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
	ok, err := h.Store.SetExp(key, expIn)
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
	ok, err := h.Store.SetExp(key, expIn)
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

	expIn, ok, err := h.Store.Exp(key)
	if err != nil {
		h.error(conn, err)
		return
	}
	if !ok {
		conn.WriteInt(-2)
		return
	}
	if expIn == 0 {
		conn.WriteInt(-1)
		return
	}

	conn.WriteInt64(int64(expIn / time.Second))
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

	expIn, ok, err := h.Store.Exp(key)
	if err != nil {
		h.error(conn, err)
		return
	}
	if !ok {
		conn.WriteInt(-2)
		return
	}
	if expIn == 0 {
		conn.WriteInt(-1)
		return
	}

	conn.WriteInt64(int64(expIn / time.Millisecond))
}

func (h *Server) Keys(conn redcon.Conn, cmd redcon.Command) {
	if !h.checkAuth(conn) {
		return
	}

	if len(cmd.Args) != 2 {
		h.wrongNumberArgs(conn, cmd)
		return
	}

	key := h.sessionKey(conn, string(cmd.Args[1]))

	keys, err := h.Store.Keys(key)
	if err != nil {
		h.error(conn, err)
		return
	}

	prefix := h.sessionKeyLen(conn)

	conn.WriteArray(len(keys))
	for _, k := range keys {
		conn.WriteBulkString(k[prefix:])
	}
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

	cursor, err := strconv.Atoi(string(cmd.Args[1]))
	if err != nil {
		h.errorString(conn, "value is not an integer or out of range")
		return
	}

	pattern, _ := getParam(cmd.Args, "match")
	pattern = h.sessionKey(conn, pattern)

	count, ok, err := getParamInt(cmd.Args, "count")
	if err != nil {
		h.errorString(conn, "value is not an integer or out of range")
		return
	}
	if !ok {
		count = 10
	}

	cursor, keys, err := h.Store.Scan(cursor, pattern, count)
	if err != nil {
		h.error(conn, err)
		return
	}

	prefix := h.sessionKeyLen(conn)

	conn.WriteArray(2)
	conn.WriteBulkString(strconv.Itoa(cursor))

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

func getParamInt(args [][]byte, name string) (int, bool, error) {
	p, ok := getParam(args, name)
	if !ok {
		return 0, false, nil
	}
	i, err := strconv.Atoi(p)
	return i, true, err
}
