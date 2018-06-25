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

type SRPConfig struct {
	p *big.Int
	g *big.Int
	db database
}

type SRPConn struct {
	net.Conn
	*sync.Mutex
	isClient bool
}

func (conn *SRPConn) handshake() error {
}

func (conn *SRPConn) clientHandshake() error {
}

func (conn *SRPConn) serverHandshake() error {
}

func (conn *SRPConn) Read(buf []byte) (int, error) {
}

func (conn *SRPConn) Write(buf []byte) (int, error) {
}

func (conn *SRPConn) Close() error {
}

func main() {
}
