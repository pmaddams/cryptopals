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

const addr = "localhost:4000"

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

// PwdBreaker represents a man-in-the-middle attacking a remote password protocol.
type PwdBreaker struct {
	*DHPrivateKey
	clientEmail string
	clientHMAC  []byte
}

// NewPwdBreaker returns a new remote password breaker.
func NewPwdBreaker(p, g *big.Int) *PwdBreaker {
	return &PwdBreaker{DHPrivateKey: DHGenerateKey(p, g)}
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		panic(err)
	}
	return res
}

// Listen prepares the breaker to accept remote password connections.
func (x *PwdBreaker) Listen(network, addr string) (net.Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return pwdListener{l, x}, nil
}

// pwdListener represents a socket ready to accept remote password connections.
type pwdListener struct {
	inner net.Listener
	x     *PwdBreaker
}

// Accept accepts an remote password connection on a listening socket.
func (l pwdListener) Accept() (net.Conn, error) {
	c, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return &pwdConn{inner: c, config: l.x, mux: new(sync.Mutex)}, nil
}

func (l pwdListener) Close() error   { return l.inner.Close() }
func (l pwdListener) Addr() net.Addr { return l.inner.Addr() }

// PwdClient represents a client implementing a remote password protocol.
type PwdClient struct {
	*DHPrivateKey
	email    string
	password string
}

// NewPwdClient returns a new remote password protocol client.
func NewPwdClient(p, g *big.Int, email, password string) *PwdClient {
	return &PwdClient{DHGenerateKey(p, g), email, password}
}

// Dial connects the remote password client to a breaker.
func (clt *PwdClient) Dial(network, addr string) (net.Conn, error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return &pwdConn{inner: c, config: clt, mux: new(sync.Mutex)}, nil
}

// pwdConn represents the state of a remote password connection.
type pwdConn struct {
	inner  net.Conn
	config interface{}
	mux    *sync.Mutex
	auth   bool
}

// handshake checks if the current remote password connection is authenticated.
// If not, it attempts to execute the authentication protocol.
// If the handshake fails, it closes the connection.
func (c *pwdConn) handshake() error {
	c.mux.Lock()
	defer c.mux.Unlock()
	if c.auth {
		return nil
	} else if x, ok := c.config.(*PwdBreaker); ok {
		if err := breakerHandshake(c.inner, x); err != nil {
			c.Close()
			return err
		}
	} else if clt, ok := c.config.(*PwdClient); ok {
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

// breakerHandshakeState represents the state that must be stored by
// the breaker in order to execute the authentication protocol.
type breakerHandshakeState struct {
	clientPub *big.Int
}

// breakerHandshake executes the authentication protocol for the breaker.
func breakerHandshake(c net.Conn, x *PwdBreaker) error {
	state := new(breakerHandshakeState)
	if err := state.receiveLoginAndSendResponse(c, x); err != nil {
		return err
	} else if err = state.receiveHMACAndSendOK(c, x); err != nil {
		return err
	}
	return nil
}

// receiveLoginAndSendResponse receives login information and sends back a salt and the server's public key.
func (state *breakerHandshakeState) receiveLoginAndSendResponse(c net.Conn, x *PwdBreaker) error {
	var clientEmail, clientPub string
	if _, err := fmt.Fscanf(c, "email: %s\npublic key: %s\n", &clientEmail, &clientPub); err != nil {
		return err
	}
	// Record the client's email address.
	x.clientEmail = clientEmail

	var ok bool
	if state.clientPub, ok = new(big.Int).SetString(clientPub, 16); !ok {
		return errors.New("receiveLoginAndSendResponse: invalid public key")
	}
	if _, err := fmt.Fprintf(c, "salt: 00\npublic key: %s\n",
		hex.EncodeToString(x.pub.Bytes())); err != nil {
		return err
	}
	return nil
}

// receiveHMACAndSendOK receives an HMAC and sends back an OK message.
func (state *breakerHandshakeState) receiveHMACAndSendOK(c net.Conn, x *PwdBreaker) error {
	var s string
	var err error
	if _, err = fmt.Fscanf(c, "hmac: %s\n", &s); err != nil {
		return err
	}
	// Record the client's HMAC.
	if x.clientHMAC, err = hex.DecodeString(s); err != nil {
		return err
	}
	fmt.Fprintln(c, "ok")

	return nil
}

// clientHandshakeState represents the state that must be stored by
// the client in order to execute the authentication protocol.
type clientHandshakeState struct {
	salt      []byte
	serverPub *big.Int
}

// clientHandshake executes the authentication protocol for the client.
func clientHandshake(c net.Conn, clt *PwdClient) error {
	state := new(clientHandshakeState)
	if err := state.sendLoginAndReceiveResponse(c, clt); err != nil {
		return err
	} else if err = state.sendHMACAndReceiveOK(c, clt); err != nil {
		return err
	}
	return nil
}

// sendLoginAndReceiveResponse sends login information and receives back a salt and the server's public key.
func (state *clientHandshakeState) sendLoginAndReceiveResponse(c net.Conn, clt *PwdClient) error {
	var err error
	if _, err = fmt.Fprintf(c, "email: %s\npublic key: %s\n",
		clt.email, hex.EncodeToString(clt.pub.Bytes())); err != nil {
		return err
	}
	var salt, serverPub string
	if _, err = fmt.Fscanf(c, "salt: %s\npublic key: %s\n", &salt, &serverPub); err != nil {
		return err
	}
	if state.salt, err = hex.DecodeString(salt); err != nil {
		return err
	}
	var ok bool
	if state.serverPub, ok = new(big.Int).SetString(serverPub, 16); !ok {
		return errors.New("ReceiveResponse: invalid public key")
	}
	return nil
}

// sendHMACAndReceiveOK sends an HMAC and receives back an OK message.
func (state *clientHandshakeState) sendHMACAndReceiveOK(c net.Conn, clt *PwdClient) error {
	h := sha256.New()
	h.Write(state.salt)
	h.Write([]byte(clt.password))
	x := new(big.Int).SetBytes(h.Sum([]byte{}))

	secret := new(big.Int).Add(clt.n, x)
	secret = secret.Exp(state.serverPub, secret, clt.p)

	h.Reset()
	h.Write(secret.Bytes())
	k := h.Sum([]byte{})

	h = hmac.New(sha256.New, state.salt)
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

// Read reads data from a remote password connection.
func (c *pwdConn) Read(buf []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.inner.Read(buf)
}

// Write writes data to a remote password connection.
func (c *pwdConn) Write(buf []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.inner.Write(buf)
}

func (c *pwdConn) Close() error                       { return c.inner.Close() }
func (c *pwdConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *pwdConn) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *pwdConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *pwdConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *pwdConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

// runProtocol runs the remote password protocol interactively.
func runProtocol(network, addr string, p, g *big.Int) error {
	x := NewPwdBreaker(p, g)
	l, err := x.Listen(network, addr)
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
		fmt.Printf("email: %s\nhmac: %x\n", x.clientEmail, x.clientHMAC)
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
	clt := NewPwdClient(p, g, userEmail, userPassword)
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

func main() {
	p, ok := new(big.Int).SetString(strings.Replace(defaultPrime, "\n", "", -1), 16)
	if !ok || !p.ProbablyPrime(0) {
		panic("invalid prime")
	}
	g, ok := new(big.Int).SetString(defaultGenerator, 16)
	if !ok {
		panic("invalid generator")
	}
	if err := runProtocol("tcp", addr, p, g); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
