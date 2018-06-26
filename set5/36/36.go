package main

import (
	"bufio"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
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
	return &srpConn{inner: conn, config: l.srv, mux: new(sync.Mutex)}, nil
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
	return &srpConn{inner: conn, config: clt, mux: new(sync.Mutex)}, nil
}

type srpConn struct {
	inner  net.Conn
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
		if err := serverHandshake(conn.inner, srv); err != nil {
			return err
		}
	} else if clt, ok := conn.config.(*SRPClient); ok {
		if err := clientHandshake(conn.inner, clt); err != nil {
			return err
		}
	} else {
		return errors.New("handshake: invalid configuration")
	}
	conn.auth = true
	return nil
}

func serverHandshake(conn net.Conn, srv *SRPServer) error {
	state := new(serverHandshakeState)
	if err := state.ReceiveLogin(conn); err != nil {
		return err
	} else if err = state.SendResponse(conn, srv); err != nil {
		return err
	} else if err = state.ReceiveHMAC(conn); err != nil {
		return err
	} else if err = state.SendOK(conn, srv); err != nil {
		return err
	}
	return nil
}

type serverHandshakeState struct {
	email      string
	r          record
	pub        crypto.PublicKey
	u          *big.Int
	clientHMAC []byte
}

func (state *serverHandshakeState) ReceiveLogin(conn net.Conn) error {
	var pub string
	_, err := fmt.Fscanf(conn, "email: %s\npub: %s\n", &(state.email), &pub)
	if err != nil {
		return err
	}
	var ok bool
	if state.pub, ok = new(big.Int).SetString(pub, 16); !ok {
		return errors.New("ReceiveLogin: invalid public key")
	}
	return nil
}

func (state *serverHandshakeState) SendResponse(conn net.Conn, srv *SRPServer) error {
	var ok bool
	if state.r, ok = srv.db[state.email]; !ok {
		return errors.New("SendResponse: user not found")
	}
	pub := new(big.Int).Mul(big.NewInt(3), state.r.v)
	pub = pub.Add(pub, srv.pub.(*big.Int))

	h := sha256.New()
	h.Write(state.pub.(*big.Int).Bytes())
	h.Write(pub.Bytes())
	state.u = new(big.Int).SetBytes(h.Sum([]byte{}))

	_, err := fmt.Fprintf(conn, "salt: %s\npub: %s\n",
		hex.EncodeToString(state.r.salt), hex.EncodeToString(pub.Bytes()))

	return err
}

func (state *serverHandshakeState) ReceiveHMAC(conn net.Conn) error {
	var clientHMAC string
	_, err := fmt.Fscanf(conn, "hmac: %s\n", &clientHMAC)
	if err != nil {
		return err
	}
	state.clientHMAC, err = hex.DecodeString(clientHMAC)
	if err != nil {
		return err
	}
	return nil
}

func (state *serverHandshakeState) SendOK(conn net.Conn, srv *SRPServer) error {
	secret := new(big.Int).Exp(state.r.v, state.u, srv.p)
	secret = secret.Mul(state.pub.(*big.Int), secret)
	secret = secret.Exp(secret, srv.n, srv.p)

	h := sha256.New()
	h.Write(secret.Bytes())
	k := h.Sum([]byte{})

	h = hmac.New(sha256.New, state.r.salt)
	h.Write(k)

	if !hmac.Equal(h.Sum([]byte{}), state.clientHMAC) {
		return errors.New("SendOK: invalid hmac")
	}
	fmt.Fprintln(conn, "ok")

	return nil
}

func clientHandshake(conn net.Conn, clt *SRPClient) error {
	state := new(clientHandshakeState)
	if err := state.SendLogin(conn, clt); err != nil {
		return err
	} else if err = state.ReceiveResponse(conn); err != nil {
		return err
	} else if err = state.SendHMAC(conn, clt); err != nil {
		return err
	} else if err = state.ReceiveOK(conn); err != nil {
		return err
	}
	return nil
}

type clientHandshakeState struct {
	salt []byte
	pub  crypto.PublicKey
	ok   bool
}

func (state *clientHandshakeState) SendLogin(conn net.Conn, clt *SRPClient) error {
	_, err := fmt.Fprintf(conn, "email: %s\npub: %s\n",
		clt.email, hex.EncodeToString(clt.pub.(*big.Int).Bytes()))

	return err
}

func (state *clientHandshakeState) ReceiveResponse(conn net.Conn) error {
	var salt, pub string
	_, err := fmt.Fscanf(conn, "salt: %s\npub: %s\n", &salt, &pub)
	if err != nil {
		return err
	}
	if state.salt, err = hex.DecodeString(salt); err != nil {
		return err
	}
	var ok bool
	if state.pub, ok = new(big.Int).SetString(pub, 16); !ok {
		return errors.New("ReceiveResponse: invalid public key")
	}
	return nil
}

func (state *clientHandshakeState) SendHMAC(conn net.Conn, clt *SRPClient) error {
	h := sha256.New()
	h.Write(clt.pub.(*big.Int).Bytes())
	h.Write(state.pub.(*big.Int).Bytes())
	u := new(big.Int).SetBytes(h.Sum([]byte{}))

	h.Reset()
	h.Write(state.salt)
	h.Write([]byte(clt.password))
	x := new(big.Int).SetBytes(h.Sum([]byte{}))

	fst := new(big.Int).Exp(clt.g, x, clt.p)
	fst = fst.Mul(big.NewInt(3), fst)
	fst = fst.Mod(fst, clt.p)
	fst = fst.Sub(state.pub.(*big.Int), fst)

	snd := new(big.Int).Mul(u, x)
	snd = snd.Add(clt.n, snd)

	secret := new(big.Int).Exp(fst, snd, clt.p)

	h.Reset()
	h.Write(secret.Bytes())
	k := h.Sum([]byte{})

	h = hmac.New(sha256.New, state.salt)
	h.Write(k)

	fmt.Fprintf(conn, "hmac: %x\n", h.Sum([]byte{}))

	return nil
}

func (state *clientHandshakeState) ReceiveOK(conn net.Conn) error {
	var s string
	if _, err := fmt.Fscanln(conn, &s); err != nil {
		return err
	}
	if s != "ok" {
		return errors.New("ReceiveOK: invalid response")
	}
	return nil
}

func (conn *srpConn) Read(buf []byte) (int, error) {
	if err := conn.handshake(); err != nil {
		return 0, err
	}
	return conn.inner.Read(buf)
}

func (conn *srpConn) Write(buf []byte) (int, error) {
	if err := conn.handshake(); err != nil {
		return 0, err
	}
	return conn.inner.Write(buf)
}

func (conn *srpConn) Close() error {
	return conn.inner.Close()
}

func (conn *srpConn) LocalAddr() net.Addr {
	return conn.inner.LocalAddr()
}

func (conn *srpConn) RemoteAddr() net.Addr {
	return conn.inner.RemoteAddr()
}

func (conn *srpConn) SetDeadline(t time.Time) error {
	return conn.inner.SetDeadline(t)
}

func (conn *srpConn) SetReadDeadline(t time.Time) error {
	return conn.inner.SetReadDeadline(t)
}

func (conn *srpConn) SetWriteDeadline(t time.Time) error {
	return conn.inner.SetWriteDeadline(t)
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
	srv.CreateUser("user", "password")

	l, err := srv.Listen("tcp", "localhost:4000")
	if err != nil {
		panic(err)
	}
	done := make(chan struct{})
	go func() {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		input := bufio.NewScanner(conn)
		for input.Scan() {
			fmt.Println(input.Text())
		}
		close(done)
	}()
	clt := NewSRPClient(p, g, "user", "password")
	conn, err := clt.Dial("tcp", "localhost:4000")
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(conn, "success")
	conn.Close()
	<-done
}
