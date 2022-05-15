package encrypt

// Package encrypt contains methods to encrypt/decrypt texts and files.

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"

	"github.com/z0rr0/ssf/encrypt/stream"
	"github.com/z0rr0/ssf/encrypt/text"
)

const (
	// saltSize is Random of salt.
	saltSize = 128
	// fileNameSize is used for storage file name.
	fileNameSize = 64
	// fileCreateAttempts is a number of attempts to create new file with unique name.
	fileCreateAttempts = 10
	// pbkdf2Iter is number of pbkdf2 iterations.
	pbkdf2Iter = 65536
	// key length for AES-256.
	aesKeyLength = 32
	// hashLength is length of file hash.
	hashLength = 32
)

var (
	// ErrSecret is an error when the secret hash is incorrect.
	ErrSecret = errors.New("failed secret")

	// ErrHash is an error when the hash is incorrect.
	ErrHash = errors.New("failed singer hash")
)

// Msg is struct with base parameter/results of encryption/decryption.
type Msg struct {
	Salt     string
	Value    string
	KeyHash  string
	DataHash string
	s        []byte
	v        []byte
	kh       []byte
	dh       []byte
}

func (m *Msg) encode(withValue bool) {
	m.Salt = hex.EncodeToString(m.s)
	m.KeyHash = hex.EncodeToString(m.kh)
	m.DataHash = hex.EncodeToString(m.dh)
	if withValue {
		m.Value = hex.EncodeToString(m.v)
	}
}

func (m *Msg) decode(withValue bool) error {
	b, err := hex.DecodeString(m.Salt)
	if err != nil {
		return fmt.Errorf("hex decode salt: %w", err)
	}
	m.s = b

	b, err = hex.DecodeString(m.KeyHash)
	if err != nil {
		return fmt.Errorf("hex decode key hash: %w", err)
	}
	m.kh = b

	b, err = hex.DecodeString(m.DataHash)
	if err != nil {
		return fmt.Errorf("hex decode data hash: %w", err)
	}
	m.dh = b

	if withValue {
		b, err = hex.DecodeString(m.Value)
		if err != nil {
			return fmt.Errorf("hex decode value: %w", err)
		}
		m.v = b
	}
	return nil
}

// StreamSigner is a wrapper for stream Read/Write and hash sum calculations together.
type StreamSigner struct {
	R     io.Reader
	W     io.Writer
	rHash sha3.ShakeHash
	wHash sha3.ShakeHash
	rDone bool
	wDone bool
}

// Read reads data from s.R. It's used for stream encryption.
func (s *StreamSigner) Read(p []byte) (n int, err error) {
	n, err = s.R.Read(p)
	if err != nil {
		return 0, err
	}
	_, err = s.rHash.Write(p[:n])
	if err != nil {
		return 0, err
	}
	s.rDone = s.rDone || n > 0
	return n, nil
}

// Write writes data to s.W. It's used for stream decryption.
func (s *StreamSigner) Write(p []byte) (n int, err error) {
	n, err = s.W.Write(p)
	if err != nil {
		return n, err
	}
	_, err = s.wHash.Write(p[:n])
	if err != nil {
		return 0, err
	}
	s.wDone = s.wDone || n > 0
	return n, nil
}

func signerHash(written bool, h sha3.ShakeHash) ([]byte, error) {
	if !written || h == nil {
		return nil, ErrHash
	}
	p := make([]byte, hashLength)
	if _, err := h.Read(p); err != nil {
		return nil, err
	}
	return p, nil
}

// ReaderHashSum calculates and returns s.R hash.
func (s *StreamSigner) ReaderHashSum() ([]byte, error) {
	return signerHash(s.rDone, s.rHash)
}

// WriterHashSum calculates and returns s.W hash.
func (s *StreamSigner) WriterHashSum() ([]byte, error) {
	return signerHash(s.wDone, s.wHash)
}

// NewStreamSigner returns new StreamSigner.
func NewStreamSigner(src io.Reader, dst io.Writer) *StreamSigner {
	var srcHash, dstHash sha3.ShakeHash
	if src != nil {
		srcHash = sha3.NewShake256()
	}
	if dst != nil {
		dstHash = sha3.NewShake256()
	}
	return &StreamSigner{
		R:     src,
		W:     dst,
		rHash: srcHash,
		wHash: dstHash,
	}
}

// Random returns n-Random bytes.
func Random(n int) ([]byte, error) {
	result := make([]byte, n)
	_, err := rand.Read(result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// createFile creates a new file with name or Random value (if name is empty) inside base path.
func createFile(base, name string) (*os.File, error) {
	var attempts = fileCreateAttempts
	if name != "" {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if name == "" {
			// no custom name, generate random one
			value, err := Random(fileNameSize)
			if err != nil {
				return nil, fmt.Errorf("random file name: %w", err)
			}
			name = hex.EncodeToString(value)
		}
		fullPath := filepath.Join(base, name)
		f, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			if !os.IsExist(err) {
				// unexpected error
				return nil, fmt.Errorf("random file creation: %w", err)
			}
			// name duplication error - do new attempt
			name = ""
		} else {
			return f, nil
		}
	}
	return nil, fmt.Errorf("can not create new file after %d attempts", fileCreateAttempts)
}

// Salt returns Random bytes.
func Salt() ([]byte, error) {
	salt, err := Random(saltSize)
	if err != nil {
		return nil, fmt.Errorf("read rand: %w", err)
	}
	return salt, nil
}

// Hash returns SHA3 ShakeSum256 check sum with length 32 bit.
func Hash(data []byte) []byte {
	b := make([]byte, hashLength)
	sha3.ShakeSum256(b, data)
	return b
}

// Key calculates and returns secret key and its SHA512 hash.
func Key(secret string, salt []byte) ([]byte, []byte) {
	key := pbkdf2.Key([]byte(secret), salt, pbkdf2Iter, aesKeyLength, sha3.New512)
	return key, Hash(append(key, salt...))
}

// Text encrypts plaintText using the secret.
// Cipher message will be returned as Msg.Value.
func Text(secret, plainText string) (*Msg, error) {
	salt, err := Salt()
	if err != nil {
		return nil, err
	}
	key, h := Key(secret, salt)
	cipherText, err := text.Encrypt([]byte(plainText), key)
	if err != nil {
		return nil, err
	}
	m := &Msg{v: cipherText, s: salt, kh: h}
	m.encode(true)
	return m, nil
}

// DecryptText returns decrypted value from Msg.Value using the secret.
// Salt in m.Salt is expected
func DecryptText(secret string, m *Msg) (string, error) {
	err := m.decode(true)
	if err != nil {
		return "", err
	}
	key, hash := Key(secret, m.s)
	if !hmac.Equal(hash, m.kh) {
		return "", ErrSecret
	}
	plainText, err := text.Decrypt(m.v, key)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

// File encrypts content from src to a new file using the secret.
// Salt and key hash are returned as Msg.Salt and Msg.KeyHash.
// The name if new file will be stored in m.Value.
func File(secret string, src io.Reader, base, name string) (*Msg, error) {
	salt, err := Salt()
	if err != nil {
		return nil, err
	}
	dst, err := createFile(base, name)
	if err != nil {
		return nil, fmt.Errorf("open file for ecryption: %w", err)
	}
	key, h := Key(secret, salt)

	signReader := NewStreamSigner(src, nil)
	err = stream.Encrypt(signReader, dst, key)
	if err != nil {
		return nil, err
	}
	dh, err := signReader.ReaderHashSum()
	if err != nil {
		return nil, err
	}

	m := &Msg{s: salt, kh: h, dh: dh, Value: dst.Name()}
	m.encode(false)
	return m, dst.Close()
}

// DecryptFile writes decrypted content of file with path from Msg.Value,
// checking Msg.KeyHash to dst using the secret and Msg.Salt.
func DecryptFile(secret string, m *Msg, dst io.Writer) error {
	err := m.decode(false)
	if err != nil {
		return err
	}
	src, err := os.Open(m.Value)
	if err != nil {
		return fmt.Errorf("open file for decryption: %w", err)
	}
	key, hash := Key(secret, m.s)
	if !hmac.Equal(hash, m.kh) {
		return ErrSecret
	}

	signWriter := NewStreamSigner(nil, dst)
	err = stream.Decrypt(src, signWriter, key)
	if err != nil {
		return err
	}

	dh, err := signWriter.WriterHashSum()
	if err != nil {
		return err
	}
	if !hmac.Equal(dh, m.dh) {
		return ErrHash
	}
	return src.Close()
}
