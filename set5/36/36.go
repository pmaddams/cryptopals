package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"net"
	"time"
)

const (
	defaultPrime = `ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff`
	defaultGenerator = `2`
)

// DHPrivateKey represents a set of Diffie-Hellman parameters and key pair.
type DHPrivateKey struct {
	p   *big.Int
	g   *big.Int
	n   *big.Int
	pub crypto.PublicKey
}

// DHGenerateKey generates a private key.
func DHGenerateKey(p, g *big.Int) *DHPrivateKey {
	n, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic(err)
	}
	pub := crypto.PublicKey(new(big.Int).Exp(g, n, p))
	return &DHPrivateKey{p, g, n, pub}
}

// Public returns the public key.
func (priv *DHPrivateKey) Public() crypto.PublicKey {
	return priv.pub
}

// Secret takes a public key and returns a shared secret.
func (priv *DHPrivateKey) Secret(pub crypto.PublicKey) []byte {
	return new(big.Int).Exp(pub.(*big.Int), priv.n, priv.p).Bytes()
}

type record struct {
	v    *big.Int
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

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		panic(err)
	}
	return res
}

func (srv *SRPServer) CreateUser(email, password string) {
	salt := RandomBytes(8)

	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))

	x := new(big.Int).SetBytes(h.Sum([]byte{}))
	v := new(big.Int).Exp(srv.g, x, srv.p)

	// Don't store the password.
	srv.db[email] = record{v, salt}
}

func (srv *SRPServer) Listen(network, addr string) (net.Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return srpListener{l, srv}, nil
}

type srpListener struct {
	l   net.Listener
	srv *SRPServer
}

func (l srpListener) Accept() (net.Conn, error) {
	conn, err := l.l.Accept()
	if err != nil {
		return nil, err
	}
	return &srpConn{conn: conn, config: l.srv}, nil
}

func (l srpListener) Close() error {
	return l.l.Close()
}

func (l srpListener) Addr() net.Addr {
	return l.l.Addr()
}

type SRPClient struct {
	*DHPrivateKey
	email    string
	password string
}

func (clt *SRPClient) Dial(network, addr string) (net.Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return &srpConn{conn: conn, config: clt}, nil
}

type srpConn struct {
	conn   net.Conn
	config interface{}
	auth   bool
}

func (conn *srpConn) handshake() error {
	if conn.auth {
		return nil
	}
	if srv, ok := conn.config.(*SRPServer); ok {
		return conn.serverHandshake(srv)
	} else if clt, ok := conn.config.(*SRPClient); ok {
		return conn.clientHandshake(clt)
	}
	return errors.New("handshake: invalid configuration")
}

type serverHandshakeState struct {
	email    string
	password string
	hmac     []byte
}

func (conn *srpConn) serverHandshake(srv *SRPServer) error {
	return nil
}

type clientHandshakeState struct {
	salt []byte
	pub  crypto.PublicKey
	ok   bool
}

func (conn *srpConn) clientHandshake(clt *SRPClient) error {
	return nil
}

func (conn *srpConn) Read(buf []byte) (int, error) {
	return 0, nil
}

func (conn *srpConn) Write(buf []byte) (int, error) {
	return 0, nil
}

func (conn *srpConn) Close() error {
	return nil
}

func (conn *srpConn) LocalAddr() net.Addr {
	return nil
}

func (conn *srpConn) RemoteAddr() net.Addr {
	return nil
}

func (conn *srpConn) SetDeadline(t time.Time) error {
	return nil
}

func (conn *srpConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (conn *srpConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func main() {
}
