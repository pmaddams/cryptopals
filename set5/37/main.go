// 37. Break SRP with a zero key

package main

import (
	"bufio"
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
	if err := breakSRP("tcp", addr, p, g); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

// breakSRP breaks the Secure Remote Password protocol interactively.
// Note that the implementation fails to check the client's public key.
func breakSRP(network, addr string, p, g *big.Int) error {
	var dbEmail, dbPassword string
	fmt.Print("database email: ")
	if _, err := fmt.Scanln(&dbEmail); err != nil {
		return err
	}
	fmt.Print("database password: ")
	if _, err := fmt.Scanln(&dbPassword); err != nil {
		return err
	}
	srv := NewSRPServer(p, g)
	srv.CreateUser(dbEmail, dbPassword)
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
		input := bufio.NewScanner(c)
		for input.Scan() {
			fmt.Println(input.Text())
		}
		close(done)
	}()
	var userEmail string
	fmt.Print("user email: ")
	if _, err := fmt.Scanln(&userEmail); err != nil {
		return err
	}
	clt := NewSRPBreaker(userEmail)
	fmt.Print("connecting...")
	c, err := clt.Dial(network, addr)
	if err != nil {
		return err
	}
	if _, err := c.Read([]byte{}); err != nil {
		fmt.Println("failure")
		return nil
	}
	fmt.Println("success")
	for input := bufio.NewScanner(os.Stdin); input.Scan(); {
		fmt.Fprintln(c, input.Text())
	}
	c.Close()
	<-done

	return nil
}

// SRPServer represents a server implementing SRP (Secure Remote Password).
type SRPServer struct {
	*DHPrivateKey
	db map[string]record
}

// record represents a database record of a user's login information.
type record struct {
	v    *big.Int
	salt []byte
}

// NewSRPServer returns a new SRP server.
func NewSRPServer(p, g *big.Int) *SRPServer {
	return &SRPServer{DHGenerateKey(p, g), make(map[string]record)}
}

// CreateUser creates a new user in the SRP server database.
func (srv *SRPServer) CreateUser(email, password string) {
	salt := RandomBytes(8)

	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	sum := new(big.Int).SetBytes(h.Sum([]byte{}))
	v := sum.Exp(srv.g, sum, srv.p)

	// Don't store the password.
	srv.db[email] = record{v, salt}
}

// Listen prepares the server to accept SRP connections.
func (srv *SRPServer) Listen(network, addr string) (net.Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &srpListener{l, srv}, nil
}

// srpServerState contains state stored by the server
// in order to execute the authentication protocol.
type srpServerState struct {
	rec       record
	clientPub *big.Int
	u         *big.Int
}

// srpServerHandshake executes the authentication protocol for the server.
func srpServerHandshake(c net.Conn, srv *SRPServer) error {
	x := new(srpServerState)
	if err := x.receiveLoginSendResponse(c, srv); err != nil {
		return err
	} else if err = x.receiveHMACSendOK(c, srv); err != nil {
		return err
	}
	return nil
}

// receiveLoginSendResponse receives login information and sends a salt and session key.
func (x *srpServerState) receiveLoginSendResponse(c net.Conn, srv *SRPServer) error {
	var email, clientPub string
	if _, err := fmt.Fscanf(c, "email: %s\npublic key: %s\n", &email, &clientPub); err != nil {
		return err
	}
	var ok bool
	if x.rec, ok = srv.db[email]; !ok {
		return errors.New("receiveLoginSendResponse: user not found")
	}
	if x.clientPub, ok = new(big.Int).SetString(clientPub, 16); !ok {
		return errors.New("receiveLoginSendResponse: invalid public key")
	}
	sessionPub := big.NewInt(3)
	sessionPub.Mul(sessionPub, x.rec.v)
	sessionPub.Add(sessionPub, srv.y)

	h := sha256.New()
	h.Write(x.clientPub.Bytes())
	h.Write(sessionPub.Bytes())
	x.u = new(big.Int).SetBytes(h.Sum([]byte{}))

	if _, err := fmt.Fprintf(c, "salt: %s\npublic key: %s\n",
		hex.EncodeToString(x.rec.salt), hex.EncodeToString(sessionPub.Bytes())); err != nil {
		return err
	}
	return nil
}

// receiveHMACSendOK receives an HMAC and sends an OK message.
func (x *srpServerState) receiveHMACSendOK(c net.Conn, srv *SRPServer) error {
	var s string
	if _, err := fmt.Fscanf(c, "hmac: %s\n", &s); err != nil {
		return err
	}
	clientHMAC, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	secret := new(big.Int).Exp(x.rec.v, x.u, srv.p)
	secret.Mul(x.clientPub, secret)
	secret.Exp(secret, srv.x, srv.p)

	k := sha256.Sum256(secret.Bytes())
	h := hmac.New(sha256.New, x.rec.salt)
	h.Write(k[:])
	if !hmac.Equal(clientHMAC, h.Sum([]byte{})) {
		return errors.New("SendOK: invalid hmac")
	}
	fmt.Fprintln(c, "ok")

	return nil
}

// srpListener represents a socket ready to accept SRP connections.
type srpListener struct {
	net.Listener
	srv *SRPServer
}

// Accept accepts an SRP connection on a listening socket.
func (x *srpListener) Accept() (net.Conn, error) {
	c, err := x.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &srpConn{c, x.srv, false, new(sync.Mutex)}, nil
}

// SRPBreaker represents a malicious client attacking SRP (Secure Remote Password).
type SRPBreaker struct {
	email string
}

// NewSRPBreaker returns a new Secure Remote Password breaker.
func NewSRPBreaker(email string) *SRPBreaker {
	return &SRPBreaker{email}
}

// Dial connects the SRP breaker to a server.
func (clt *SRPBreaker) Dial(network, addr string) (net.Conn, error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return &srpConn{c, clt, false, new(sync.Mutex)}, nil
}

// srpBreakerState contains state stored by the breaker
// in order to execute the authentication protocol.
type srpBreakerState struct {
	salt []byte
}

// srpBreakerHandshake executes the authentication protocol for the breaker.
func srpBreakerHandshake(c net.Conn, clt *SRPBreaker) error {
	x := new(srpBreakerState)
	if err := x.sendLoginReceiveResponse(c, clt); err != nil {
		return err
	} else if err = x.sendHMACReceiveOK(c, clt); err != nil {
		return err
	}
	return nil
}

// sendLoginReceiveResponse sends login information and receives a salt and session key.
func (x *srpBreakerState) sendLoginReceiveResponse(c net.Conn, clt *SRPBreaker) error {
	var err error
	if _, err = fmt.Fprintf(c, "email: %s\npublic key: 0\n", clt.email); err != nil {
		return err
	}
	var salt, unused string
	if _, err = fmt.Fscanf(c, "salt: %s\npublic key: %s\n", &salt, &unused); err != nil {
		return err
	}
	if x.salt, err = hex.DecodeString(salt); err != nil {
		return err
	}
	return nil
}

// sendHMACReceiveOK sends an HMAC and receives an OK message.
func (x *srpBreakerState) sendHMACReceiveOK(c net.Conn, clt *SRPBreaker) error {
	k := sha256.Sum256([]byte{})
	h := hmac.New(sha256.New, x.salt)
	h.Write(k[:])

	fmt.Fprintf(c, "hmac: %x\n", h.Sum([]byte{}))

	var s string
	if _, err := fmt.Fscanln(c, &s); err != nil {
		return err
	} else if s != "ok" {
		return errors.New("ReceiveOK: invalid response")
	}
	return nil
}

// srpConn represents the state of an SRP connection.
type srpConn struct {
	net.Conn
	config interface{}
	auth   bool
	*sync.Mutex
}

// Read reads data from an SRP connection.
func (x *srpConn) Read(buf []byte) (int, error) {
	if err := x.handshake(); err != nil {
		return 0, err
	}
	return x.Conn.Read(buf)
}

// Write writes data to an SRP connection.
func (x *srpConn) Write(buf []byte) (int, error) {
	if err := x.handshake(); err != nil {
		return 0, err
	}
	return x.Conn.Write(buf)
}

// handshake checks if the current SRP connection is authenticated.
// If not, it attempts to execute the authentication protocol.
// If the handshake fails, it closes the connection.
func (x *srpConn) handshake() error {
	x.Lock()
	defer x.Unlock()
	if x.auth {
		return nil
	} else if srv, ok := x.config.(*SRPServer); ok {
		if err := srpServerHandshake(x.Conn, srv); err != nil {
			x.Close()
			return err
		}
	} else if clt, ok := x.config.(*SRPBreaker); ok {
		if err := srpBreakerHandshake(x.Conn, clt); err != nil {
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

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}
