package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"unsafe"
)

// PrefixSHA1 returns a new SHA-1 hash using register values from an existing checksum.
func PrefixSHA1(sum []byte) (hash.Hash, error) {
	if len(sum) != sha1.Size {
		return nil, errors.New("PrefixSHA1: invalid checksum")
	}
	src := [5]uint32{
		binary.BigEndian.Uint32(sum[:4]),
		binary.BigEndian.Uint32(sum[4:8]),
		binary.BigEndian.Uint32(sum[8:12]),
		binary.BigEndian.Uint32(sum[12:16]),
		binary.BigEndian.Uint32(sum[16:20]),
	}
	h := sha1.New()

	dst := reflect.ValueOf(&h).Elem().Elem().Elem().Field(0)
	dst = reflect.NewAt(dst.Type(), unsafe.Pointer(dst.UnsafeAddr())).Elem()
	dst.Set(reflect.ValueOf(src))

	return h, nil
}

func main() {
	h, err := PrefixSHA1(bytes.Repeat([]byte{0}, 20))
	if err != nil {
		panic(err)
	}
	fmt.Println(h)
}
