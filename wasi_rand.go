// wasi_rand: random number generator for TinyGo/WASI
//
// This is essentially the HASH_DRBG construction instantiated with the SHA-512 hash function,
// but with a 64-bit non-deterministic counter.

package wasi_rand

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"unsafe"
)

//go:wasm-module wasi_snapshot_preview1
//export random_get
func _wasi_random_get(buf unsafe.Pointer, len uint32) (errno uint16)

func getRandom(p []byte) error {
	if _wasi_random_get(unsafe.Pointer(&p[0]), uint32(len(p))) != 0 {
		return errors.New("no entropy source")
	}
	return nil
}

type reader struct {
	mu          sync.Mutex
	block       [64]byte
	c           [64]byte
	ctr         uint64
	initialized bool
}

func (r *reader) update() {
	hasher := sha512.New()
	hasher.Write([]byte{0x03})
	var hv [64]byte
	copy(hv[:], hasher.Sum(r.block[:]))
	xctr := r.ctr
	for i := 0; i < 64; i++ {
		r.block[i] ^= hv[i] ^ r.c[i] ^ byte(xctr)
		hv[i] = 0
		xctr >>= 8
	}
	if r.ctr == 0 {
		r.Reseed()
	}
	r.ctr += 1
}

func (r *reader) seedIfNeeded() error {
	if r.initialized {
		return nil
	}
	if err := getRandom(r.block[0:64]); err != nil {
		return err
	}
	hasher := sha512.New()
	hasher.Write([]byte{0x00})
	copy(r.c[:], hasher.Sum(r.block[:]))
	hasher.Reset()
	hasher.Write([]byte{0x04})
	var ctr0 [8]byte
	copy(ctr0[:], hasher.Sum(r.block[:]))
	r.ctr = binary.LittleEndian.Uint64(ctr0[:])
	r.update()
	r.initialized = true
	return nil
}

/// Reseed - Mix additional entropy into the state.
func (r *reader) Reseed() error {
	hasher := sha512.New()
	hasher.Write([]byte{0x01})

	r.mu.Lock()
	defer r.mu.Unlock()

	hasher.Write(r.block[:])
	if err := getRandom(r.block[0:64]); err != nil {
		return err
	}
	hasher.Write(r.block[:])
	copy(r.block[:], hasher.Sum([]byte{}))
	hasher.Reset()
	hasher.Write([]byte{0x00})
	copy(r.c[:], hasher.Sum(r.block[:]))
	hasher.Reset()
	hasher.Write([]byte{0x04})
	var ctr0 [8]byte
	copy(ctr0[:], hasher.Sum(r.block[:]))
	r.ctr = binary.LittleEndian.Uint64(ctr0[:])
	return nil
}

func (r *reader) Read(b []byte) (int, error) {
	r.mu.Lock()
	if err := r.seedIfNeeded(); err != nil {
		r.mu.Unlock()
		return -1, err
	}
	var v0 [64]byte
	copy(v0[:], r.block[:])
	r.update()
	r.mu.Unlock()

	ictr := uint64(0)
	var v [64]byte
	pos := 0
	hasher := sha512.New()
	for left := len(b); left > 0; {
		copy(v[:], v0[:])
		xictr := ictr
		for i := 0; i < 64; i++ {
			v[i] ^= byte(xictr)
			xictr >>= 8
		}
		ictr += 1
		hasher.Reset()
		hasher.Write(v[:])
		copy(v[:], hasher.Sum([]byte{}))
		len := left
		if len > 64 {
			len = 64
		}
		copy(b[pos:pos+len], v[0:len])
		left -= len
		pos += len

	}
	return len(b), nil
}

func newReader() io.Reader {
	return &reader{}
}

var Reader io.Reader = newReader()

/// Read - Fill `b` with cryptographically-secure random bytes.
func Read(b []byte) (n int, err error) {
	return io.ReadFull(Reader, b)
}
