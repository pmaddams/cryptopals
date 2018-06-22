package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"log"
	"math/big"
	"net"
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

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		panic(err)
	}
	return res
}

// srp represents a generic SRP (Secure Remote Password) communicator.
type srp struct {
	*DHPrivateKey
	*gob.Decoder
	*gob.Encoder
	*log.Logger
	email string
	salt  []byte
}

// SRPServer represents an SRP server.
type SRPServer struct {
	srp
	verifier *big.Int
}

// NewSRPServer returns an SRP server.
func NewSRPServer(p, g *big.Int, conn net.Conn, log *log.Logger, email, password string) *SRPServer {
	dh := DHGenerateKey(p, g)
	salt := RandomBytes(8)

	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	x := new(big.Int).SetBytes(h.Sum([]byte{}))
	verifier := new(big.Int).Exp(dh.g, x, dh.p)

	return &SRPServer{
		srp{
			dh,
			gob.NewDecoder(conn),
			gob.NewEncoder(conn),
			log,
			email,
			salt,
		},
		verifier,
	}
}

// SRPClient represents an SRP client.
type SRPClient struct {
	srp
	password string
}

// NewSRPClient returns an SRP client.
func NewSRPClient(p, g *big.Int, conn net.Conn, log *log.Logger, email, password string) *SRPClient {
	return &SRPClient{
		srp{
			DHGenerateKey(p, g),
			gob.NewDecoder(conn),
			gob.NewEncoder(conn),
			log,
			email,
			nil,
		},
		password,
	}
}

func main() {
}
