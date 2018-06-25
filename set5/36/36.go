package main

import (
	"math/big"
	"net"
	"sync"
)

type record struct {
	v *big.Int
	salt []byte
}

type database map[string]record

type SRPServer struct {
	*DHPrivateKey
	db database
}

func NewSRPServer(p, g *big.Int) *SRPServer {
	return &SRPServer{DHGenerateKey(p, g), make(map[string]record)}
}

func (srv *SRPServer) CreateUser(email, password string) {
	salt := RandomBytes(8)
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	x := new(big.Int).SetBytes(h.Sum([]byte{}))
	v := new(big.Int).Exp(srv.g, x, srv.p)

	// Don't store the user's password.
	srv.db[email] = record{v, salt}
}

type srpListener struct {
	l   net.Listener
	srv *SRPServer
}

func (srv *SRPServer) Listen(network, addr string) (net.Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return srpListener{l, srv}
}

type srpConn struct {
	conn   net.Conn
	config interface{}
	auth   bool
}

func (l srpListener) Accept() (net.Conn, error) {
	conn, err := l.l.Accept()
	if err != nil {
		return nil, err
	}
	return srpConn{conn, srv, false}
}

type SRPClient struct {
	*DHPrivateKey
	email string
	password string
}

func (clt *SRPClient) Dial(network, addr string) (net.Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return srpConn{conn, clt, false}
}

func (conn srpConn) handshake() error {
	// TODO: concurrency
	if conn.auth {
		return nil
	}
}

func (conn srpConn) serverHandshake() error {
}

func (conn srpConn) clientHandshake() error {
}

func (conn srpConn) Read(buf []byte) (int, error) {
}

func (conn srpConn) Write(buf []byte) (int, error) {
}

func (conn srpConn) Close() error {
}

func main() {
}
