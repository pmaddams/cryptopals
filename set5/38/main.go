// 38. Offline dictionary attack on simplified SRP

package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
)

const (
	file    = "passwords.txt"
	addr    = "localhost:4000"
	dhPrime = `ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff`
	dhGenerator = `2`
)

func main() {
	p, err := ParseBigInt(dhPrime, 16)
	if err != nil {
		panic(err)
	}
	g, err := ParseBigInt(dhGenerator, 16)
	if err != nil {
		panic(err)
	}
	if err := breakPassword("tcp", addr, p, g, file); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

// breakPassword runs the remote password protocol and attempts to crack the user's password.
func breakPassword(network, addr string, p, g *big.Int, file string) error {
	srv := NewPWBreaker(p, g)
	l, err := srv.Listen(network, addr)
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		if _, err := c.Read([]byte{}); err != nil {
			log.Fatal(err)
		}
		fmt.Print("cracking password...")
		password, err := srv.Password(file)
		if err != nil {
			fmt.Println("failure")
		} else {
			fmt.Println(password)
		}
		close(done)
	}()
	var userEmail, userPassword string
	fmt.Print("user email: ")
	if _, err := fmt.Scanln(&userEmail); err != nil {
		return err
	}
	fmt.Print("user password: ")
	if _, err := fmt.Scanln(&userPassword); err != nil {
		return err
	}
	clt := NewPWClient(p, g, userEmail, userPassword)
	c, err := clt.Dial(network, addr)
	if err != nil {
		return err
	}
	if _, err := c.Read([]byte{}); err != nil {
		return err
	}
	c.Close()
	<-done

	return nil
}

// PWBreaker represents a man-in-the-middle attacking a remote password protocol.
type PWBreaker struct {
	*DHPrivateKey
	clientEmail string
	clientPub   *big.Int
	clientHMAC  []byte
}

// NewPWBreaker returns a new remote password breaker.
func NewPWBreaker(p, g *big.Int) *PWBreaker {
	return &PWBreaker{
		DHPrivateKey: &DHPrivateKey{
			DHPublicKey{
				p: p,
				g: g,
				y: g,
			},
			big.NewInt(1),
		},
	}
}

// Password takes a file containing passwords and returns
// the line, if any, that matches the client's password.
func (srv *PWBreaker) Password(file string) (string, error) {
	if srv.clientEmail == "" || srv.clientPub == nil || srv.clientHMAC == nil {
		return "", errors.New("Password: not enough information")
	}
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	salt := []byte{0}
	h1 := sha256.New()
	h2 := hmac.New(sha256.New, salt)
	for input := bufio.NewScanner(f); input.Scan(); {
		password := input.Text()

		h1.Reset()
		h1.Write(salt)
		h1.Write([]byte(password))

		secret := new(big.Int).SetBytes(h1.Sum([]byte{}))
		secret.Exp(srv.g, secret, srv.p)
		secret.Mul(srv.clientPub, secret)
		secret.Mod(secret, srv.p)

		h1.Reset()
		h1.Write(secret.Bytes())
		h2.Reset()
		h2.Write(h1.Sum([]byte{}))
		if bytes.Equal(h2.Sum([]byte{}), srv.clientHMAC) {
			return password, nil
		}
	}
	return "", errors.New("Password: not found")
}

// Listen prepares the breaker to accept remote password connections.
func (srv *PWBreaker) Listen(network, addr string) (net.Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return pwListener{l, srv}, nil
}

// pwBreakerState contains state stored by the breaker
// in order to execute the authentication protocol.
type pwBreakerState struct{}

// pwBreakerHandshake executes the authentication protocol for the breaker.
func pwBreakerHandshake(c net.Conn, srv *PWBreaker) error {
	x := new(pwBreakerState)
	if err := x.receiveLoginSendResponse(c, srv); err != nil {
		return err
	} else if err = x.receiveHMACSendOK(c, srv); err != nil {
		return err
	}
	return nil
}

// receiveLoginSendResponse receives login information and sends a salt and the server's public key.
func (x *pwBreakerState) receiveLoginSendResponse(c net.Conn, srv *PWBreaker) error {
	var clientEmail, clientPub string
	if _, err := fmt.Fscanf(c, "email: %s\npublic key: %s\n", &clientEmail, &clientPub); err != nil {
		return err
	}
	// Record the client's email address.
	srv.clientEmail = clientEmail

	// Record the client's public key.
	var ok bool
	if srv.clientPub, ok = new(big.Int).SetString(clientPub, 16); !ok {
		return errors.New("receiveLoginSendResponse: invalid public key")
	}
	if _, err := fmt.Fprintf(c, "salt: 00\npublic key: %s\n",
		hex.EncodeToString(srv.y.Bytes())); err != nil {
		return err
	}
	return nil
}

// receiveHMACSendOK receives an HMAC and sends an OK message.
func (x *pwBreakerState) receiveHMACSendOK(c net.Conn, srv *PWBreaker) error {
	var s string
	var err error
	if _, err = fmt.Fscanf(c, "hmac: %s\n", &s); err != nil {
		return err
	}
	// Record the client's HMAC.
	if srv.clientHMAC, err = hex.DecodeString(s); err != nil {
		return err
	}
	fmt.Fprintln(c, "ok")

	return nil
}

// pwListener represents a socket ready to accept remote password connections.
type pwListener struct {
	net.Listener
	srv *PWBreaker
}

// Accept accepts a remote password connection on a listening socket.
func (x pwListener) Accept() (net.Conn, error) {
	c, err := x.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &pwConn{c, x.srv, false, new(sync.Mutex)}, nil
}

// PWClient represents a client implementing a remote password protocol.
type PWClient struct {
	*DHPrivateKey
	email    string
	password string
}

// NewPWClient returns a new remote password protocol client.
func NewPWClient(p, g *big.Int, email, password string) *PWClient {
	return &PWClient{DHGenerateKey(p, g), email, password}
}

// Dial connects the remote password client to a breaker.
func (clt *PWClient) Dial(network, addr string) (net.Conn, error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return &pwConn{c, clt, false, new(sync.Mutex)}, nil
}

// pwClientState contains state stored by the client
// in order to execute the authentication protocol.
type pwClientState struct {
	salt      []byte
	serverPub *big.Int
}

// pwClientHandshake executes the authentication protocol for the client.
func pwClientHandshake(c net.Conn, clt *PWClient) error {
	x := new(pwClientState)
	if err := x.sendLoginReceiveResponse(c, clt); err != nil {
		return err
	} else if err = x.sendHMACReceiveOK(c, clt); err != nil {
		return err
	}
	return nil
}

// sendLoginReceiveResponse sends login information and receives a salt and the server's public key.
func (x *pwClientState) sendLoginReceiveResponse(c net.Conn, clt *PWClient) error {
	var err error
	if _, err = fmt.Fprintf(c, "email: %s\npublic key: %s\n",
		clt.email, hex.EncodeToString(clt.y.Bytes())); err != nil {
		return err
	}
	var salt, serverPub string
	if _, err = fmt.Fscanf(c, "salt: %s\npublic key: %s\n", &salt, &serverPub); err != nil {
		return err
	}
	if x.salt, err = hex.DecodeString(salt); err != nil {
		return err
	}
	var ok bool
	if x.serverPub, ok = new(big.Int).SetString(serverPub, 16); !ok {
		return errors.New("ReceiveResponse: invalid public key")
	}
	return nil
}

// sendHMACReceiveOK sends an HMAC and receives an OK message.
func (x *pwClientState) sendHMACReceiveOK(c net.Conn, clt *PWClient) error {
	h := sha256.New()
	h.Write(x.salt)
	h.Write([]byte(clt.password))
	sum := new(big.Int).SetBytes(h.Sum([]byte{}))

	secret := new(big.Int).Add(clt.x, sum)
	secret.Exp(x.serverPub, secret, clt.p)

	h.Reset()
	h.Write(secret.Bytes())
	k := h.Sum([]byte{})
	h = hmac.New(sha256.New, x.salt)
	h.Write(k)

	fmt.Fprintf(c, "hmac: %x\n", h.Sum([]byte{}))

	var s string
	if _, err := fmt.Fscanln(c, &s); err != nil {
		return err
	} else if s != "ok" {
		return errors.New("ReceiveOK: invalid response")
	}
	return nil
}

// pwConn represents the state of a remote password connection.
type pwConn struct {
	net.Conn
	config interface{}
	auth   bool
	*sync.Mutex
}

// Read reads data from an SRP connection.
func (x *pwConn) Read(buf []byte) (int, error) {
	if err := x.handshake(); err != nil {
		return 0, err
	}
	return x.Conn.Read(buf)
}

// Write writes data to an SRP connection.
func (x *pwConn) Write(buf []byte) (int, error) {
	if err := x.handshake(); err != nil {
		return 0, err
	}
	return x.Conn.Write(buf)
}

// handshake checks if the current remote password connection is authenticated.
// If not, it attempts to execute the authentication protocol.
// If the handshake fails, it closes the connection.
func (x *pwConn) handshake() error {
	x.Lock()
	defer x.Unlock()
	if x.auth {
		return nil
	} else if srv, ok := x.config.(*PWBreaker); ok {
		if err := pwBreakerHandshake(x.Conn, srv); err != nil {
			x.Close()
			return err
		}
	} else if clt, ok := x.config.(*PWClient); ok {
		if err := pwClientHandshake(x.Conn, clt); err != nil {
			x.Close()
			return err
		}
	} else {
		x.Close()
		return errors.New("handshake: invalid configuration")
	}
	x.auth = true
	return nil
}

// DHPublicKey represents the public part of a Diffie-Hellman key pair.
type DHPublicKey struct {
	p *big.Int
	g *big.Int
	y *big.Int
}

// DHPrivateKey represents a Diffie-Hellman key pair.
type DHPrivateKey struct {
	DHPublicKey
	x *big.Int
}

// DHGenerateKey generates a private key.
func DHGenerateKey(p, g *big.Int) *DHPrivateKey {
	x, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic(err)
	}
	y := new(big.Int).Exp(g, x, p)

	return &DHPrivateKey{DHPublicKey{p, g, y}, x}
}

// Secret takes a public key and returns a shared secret.
func (priv *DHPrivateKey) Secret(pub *DHPublicKey) []byte {
	return new(big.Int).Exp(pub.y, priv.x, priv.p).Bytes()
}

// Public returns a public key.
func (priv *DHPrivateKey) Public() *DHPublicKey {
	return &priv.DHPublicKey
}

// ParseBigInt converts a string to an arbitrary-precision integer.
func ParseBigInt(s string, base int) (*big.Int, error) {
	if base < 0 || base > 16 {
		return nil, errors.New("ParseBigInt: invalid base")
	}
	s = strings.Replace(s, "\n", "", -1)
	z, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, errors.New("ParseBigInt: invalid string")
	}
	return z, nil
}
