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
	pub *big.Int
}

// DHGenerateKey generates a private key.
func DHGenerateKey(p, g *big.Int) *DHPrivateKey {
	n, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic(err)
	}
	pub := new(big.Int).Exp(g, n, p)
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
	c, err := l.l.Accept()
	if err != nil {
		return nil, err
	}
	return &srpConn{inner: c, config: l.srv, mux: new(sync.Mutex)}, nil
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
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return &srpConn{inner: c, config: clt, mux: new(sync.Mutex)}, nil
}

type srpConn struct {
	inner  net.Conn
	config interface{}
	mux    *sync.Mutex
	auth   bool
}

func (c *srpConn) handshake() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.auth {
		return nil
	} else if srv, ok := c.config.(*SRPServer); ok {
		if err := serverHandshake(c.inner, srv); err != nil {
			c.Close()
			return err
		}
	} else if clt, ok := c.config.(*SRPClient); ok {
		if err := clientHandshake(c.inner, clt); err != nil {
			c.Close()
			return err
		}
	} else {
		c.Close()
		return errors.New("handshake: invalid configuration")
	}
	c.auth = true
	return nil
}

type serverHandshakeState struct {
	rec       record
	clientPub *big.Int
	u         *big.Int
}

func serverHandshake(c net.Conn, srv *SRPServer) error {
	state := new(serverHandshakeState)
	if err := state.receiveLoginAndSendResponse(c, srv); err != nil {
		return err
	} else if err = state.receiveHMACAndSendOK(c, srv); err != nil {
		return err
	}
	return nil
}

func (state *serverHandshakeState) receiveLoginAndSendResponse(c net.Conn, srv *SRPServer) error {
	var email, clientPub string
	if _, err := fmt.Fscanf(c, "email: %s\npublic key: %s\n", &email, &clientPub); err != nil {
		return err
	}
	var ok bool
	if state.rec, ok = srv.db[email]; !ok {
		return errors.New("receiveLoginAndSendResponse: user not found")
	}
	if state.clientPub, ok = new(big.Int).SetString(clientPub, 16); !ok {
		return errors.New("receiveLoginAndSendResponse: invalid public key")
	}
	sessionPub := new(big.Int).Mul(big.NewInt(3), state.rec.v)
	sessionPub = sessionPub.Add(sessionPub, srv.pub)

	h := sha256.New()
	h.Write(state.clientPub.Bytes())
	h.Write(sessionPub.Bytes())
	state.u = new(big.Int).SetBytes(h.Sum([]byte{}))

	if _, err := fmt.Fprintf(c, "salt: %s\npublic key: %s\n",
		hex.EncodeToString(state.rec.salt), hex.EncodeToString(sessionPub.Bytes())); err != nil {
		return err
	}
	return nil
}

func (state *serverHandshakeState) receiveHMACAndSendOK(c net.Conn, srv *SRPServer) error {
	var s string
	if _, err := fmt.Fscanf(c, "hmac: %s\n", &s); err != nil {
		return err
	}
	clientHMAC, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	secret := new(big.Int).Exp(state.rec.v, state.u, srv.p)
	secret = secret.Mul(state.clientPub, secret)
	secret = secret.Exp(secret, srv.n, srv.p)

	h := sha256.New()
	h.Write(secret.Bytes())
	k := h.Sum([]byte{})

	h = hmac.New(sha256.New, state.rec.salt)
	h.Write(k)
	if !hmac.Equal(clientHMAC, h.Sum([]byte{})) {
		return errors.New("SendOK: invalid hmac")
	}
	fmt.Fprintln(c, "ok")

	return nil
}

type clientHandshakeState struct {
	salt       []byte
	sessionPub *big.Int
}

func clientHandshake(c net.Conn, clt *SRPClient) error {
	state := new(clientHandshakeState)
	if err := state.sendLoginAndReceiveResponse(c, clt); err != nil {
		return err
	} else if err = state.sendHMACAndReceiveOK(c, clt); err != nil {
		return err
	}
	return nil
}

func (state *clientHandshakeState) sendLoginAndReceiveResponse(c net.Conn, clt *SRPClient) error {
	var err error
	if _, err = fmt.Fprintf(c, "email: %s\npublic key: %s\n",
		clt.email, hex.EncodeToString(clt.pub.Bytes())); err != nil {
		return err
	}
	var salt, sessionPub string
	if _, err = fmt.Fscanf(c, "salt: %s\npublic key: %s\n", &salt, &sessionPub); err != nil {
		return err
	}
	if state.salt, err = hex.DecodeString(salt); err != nil {
		return err
	}
	var ok bool
	if state.sessionPub, ok = new(big.Int).SetString(sessionPub, 16); !ok {
		return errors.New("ReceiveResponse: invalid public key")
	}
	return nil
}

func (state *clientHandshakeState) sendHMACAndReceiveOK(c net.Conn, clt *SRPClient) error {
	h := sha256.New()
	h.Write(clt.pub.Bytes())
	h.Write(state.sessionPub.Bytes())
	u := new(big.Int).SetBytes(h.Sum([]byte{}))

	h.Reset()
	h.Write(state.salt)
	h.Write([]byte(clt.password))
	x := new(big.Int).SetBytes(h.Sum([]byte{}))

	fst := new(big.Int).Exp(clt.g, x, clt.p)
	fst = fst.Mul(big.NewInt(3), fst)
	fst = fst.Sub(state.sessionPub, fst)
	snd := new(big.Int).Mul(u, x)
	snd = snd.Add(clt.n, snd)
	secret := new(big.Int).Exp(fst, snd, clt.p)

	h.Reset()
	h.Write(secret.Bytes())
	k := h.Sum([]byte{})

	h = hmac.New(sha256.New, state.salt)
	h.Write(k)
	fmt.Fprintf(c, "hmac: %x\n", h.Sum([]byte{}))

	var s string
	if _, err := fmt.Fscanln(c, &s); err != nil {
		return err
	}
	if s != "ok" {
		return errors.New("ReceiveOK: invalid response")
	}
	return nil
}

func (c *srpConn) Read(buf []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.inner.Read(buf)
}

func (c *srpConn) Write(buf []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.inner.Write(buf)
}

func (c *srpConn) Close() error                       { return c.inner.Close() }
func (c *srpConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *srpConn) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *srpConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *srpConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *srpConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

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
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		input := bufio.NewScanner(c)
		for input.Scan() {
			fmt.Println(input.Text())
		}
		close(done)
	}()
	clt := NewSRPClient(p, g, "user", "password")
	c, err := clt.Dial("tcp", "localhost:4000")
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(c, "success")
	c.Close()
	<-done
}
