package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
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
	return &srpConn{conn: conn, config: l.srv, mux: new(sync.Mutex)}, nil
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

func NewSRPClient(p, g *big.Int, email, password string) *SRPClient {
	return &SRPClient{DHGenerateKey(p, g), email, password}
}

func (clt *SRPClient) Dial(network, addr string) (net.Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return &srpConn{conn: conn, config: clt, mux: new(sync.Mutex)}, nil
}

type srpConn struct {
	conn   net.Conn
	config interface{}
	mux    *sync.Mutex
	auth   bool
}

func (conn *srpConn) handshake() error {
	conn.mux.Lock()
	defer conn.mux.Unlock()

	if conn.auth {
		return nil
	}
	if srv, ok := conn.config.(*SRPServer); ok {
		if err := conn.serverHandshake(srv); err != nil {
			return err
		}
	} else if clt, ok := conn.config.(*SRPClient); ok {
		if err := conn.clientHandshake(clt); err != nil {
			return err
		}
	} else {
		return errors.New("handshake: invalid configuration")
	}
	conn.auth = true
	return nil
}

func (conn *srpConn) serverHandshake(srv *SRPServer) error {
	state := new(serverHandshakeState)
	if err := state.ReceiveLogin(); err != nil {
		return err
	} else if err = state.SendResponse(); err != nil {
		return err
	} else if err = state.ReceiveHMAC(); err != nil {
		return err
	} else if err = state.SendOK(); err != nil {
		return err
	}
	return nil
}

type serverHandshakeState struct {
	email    string
	password string
	hmac     []byte
}

func (state *serverHandshakeState) ReceiveLogin() error {
	return nil
}

func (state *serverHandshakeState) SendResponse() error {
	return nil
}

func (state *serverHandshakeState) ReceiveHMAC() error {
	return nil
}

func (state *serverHandshakeState) SendOK() error {
	return nil
}

func (conn *srpConn) clientHandshake(clt *SRPClient) error {
	state := new(clientHandshakeState)
	if err := state.SendLogin(); err != nil {
		return err
	} else if err = state.ReceiveResponse(); err != nil {
		return err
	} else if err = state.SendHMAC(); err != nil {
		return err
	} else if err = state.ReceiveOK(); err != nil {
		return err
	}
	return nil
}

type clientHandshakeState struct {
	salt []byte
	pub  crypto.PublicKey
	ok   bool
}

func (state *clientHandshakeState) SendLogin() error {
	return nil
}

func (state *clientHandshakeState) ReceiveResponse() error {
	return nil
}

func (state *clientHandshakeState) SendHMAC() error {
	return nil
}

func (state *clientHandshakeState) ReceiveOK() error {
	return nil
}

func (conn *srpConn) Read(buf []byte) (int, error) {
	if err := conn.handshake(); err != nil {
		return 0, err
	}
	return conn.conn.Read(buf)
}

func (conn *srpConn) Write(buf []byte) (int, error) {
	if err := conn.handshake(); err != nil {
		return 0, err
	}
	return conn.conn.Write(buf)
}

func (conn *srpConn) Close() error {
	return conn.conn.Close()
}

func (conn *srpConn) LocalAddr() net.Addr {
	return conn.conn.LocalAddr()
}

func (conn *srpConn) RemoteAddr() net.Addr {
	return conn.conn.RemoteAddr()
}

func (conn *srpConn) SetDeadline(t time.Time) error {
	return conn.conn.SetDeadline(t)
}

func (conn *srpConn) SetReadDeadline(t time.Time) error {
	return conn.conn.SetReadDeadline(t)
}

func (conn *srpConn) SetWriteDeadline(t time.Time) error {
	return conn.conn.SetWriteDeadline(t)
}

func main() {
	p, ok := new(big.Int).SetString(strings.Replace(defaultPrime, "\n", "", -1), 16)
	if !ok || !p.ProbablyPrime(0) {
		panic("invalid prime")
	}
	g, ok := new(big.Int).SetString(defaultGenerator, 16)
	if !ok {
		panic("invalid generator")
	}
	srv := NewSRPServer(p, g)
	l, err := srv.Listen("tcp", "localhost:4000")
	if err != nil {
		panic(err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			panic(err)
		}
		if _, err := io.Copy(os.Stdout, conn); err != nil {
			panic(err)
		}
	}()
	clt := NewSRPClient(p, g, "user", "password")
	conn, err := clt.Dial("tcp", "localhost:4000")
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(conn, "hello world")
}
