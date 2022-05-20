package config

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite3 driver package
)

var (
	// ErrSizeLimit is an error, when storage limit is reached.
	ErrSizeLimit = errors.New("size limit is reached")
)

// server is HTTP server configuration.
type server struct {
	Host    string `toml:"host"`
	Port    int    `toml:"port"`
	Timeout int    `toml:"timeout"`
}

// Storage is storage configuration params struct.
type Storage struct {
	sync.Mutex
	File  string `toml:"file"`
	Dir   string `toml:"dir"`
	Size  int64  `toml:"size"`
	limit int64
	Db    *sql.DB
}

// String returns base info about Storage.
func (s *Storage) String() string {
	return fmt.Sprintf("database=%s, files=%s, limit=%d/%d", s.File, s.Dir, s.limit, s.Size)
}

// Limit updates storage limit and returns and error if it's reached.
func (s *Storage) Limit(v int64) error {
	s.Lock()
	defer s.Unlock()

	limit := s.limit + v
	if limit > s.Size {
		return fmt.Errorf("storage limit=%d is reached [%v + %v]: %w", s.Size, s.limit, v, ErrSizeLimit)
	}
	s.limit = limit
	return nil
}

// initLimits sets initial limit by current storage state.
func (s *Storage) initLimits() error {
	s.Lock()
	defer s.Unlock()

	dirEntries, err := os.ReadDir(s.Dir)
	if err != nil {
		return err
	}

	var fileInfo fs.FileInfo
	s.Size = s.Size << 20 // megabytes -> bytes

	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			continue // skip directories
		}
		fileInfo, err = dirEntry.Info()
		if err != nil {
			return err
		}
		s.limit += fileInfo.Size()
	}
	return nil
}

// Settings struct is base service settings.
type Settings struct {
	TTL      int    `toml:"ttl"`
	Times    int    `toml:"times"`
	Size     int    `toml:"size"`
	Salt     string `toml:"salt"`
	GC       int    `toml:"gc"`
	PassLen  int    `toml:"passlen"`
	Shutdown int    `toml:"shutdown"`
}

// Config is a main configuration structure.
type Config struct {
	Server   server   `toml:"server"`
	Storage  Storage  `toml:"Storage"`
	Settings Settings `toml:"settings"`
}

// Addr returns service's net address.
func (c *Config) Addr() string {
	return net.JoinHostPort(c.Server.Host, fmt.Sprint(c.Server.Port))
}

// Close frees resources.
func (c *Config) Close() error {
	return c.Storage.Db.Close()
}

// Timeout is service timeout.
func (c *Config) Timeout() time.Duration {
	return time.Duration(c.Server.Timeout) * time.Second
}

// GCPeriod is gc period in seconds.
func (c *Config) GCPeriod() time.Duration {
	return time.Duration(c.Settings.GC) * time.Second
}

// MaxFileSize returns max file size.
func (c *Config) MaxFileSize() int {
	return c.Settings.Size << 20
}

// Secret returns string with salt.
func (c *Config) Secret(p string) string {
	return p + c.Settings.Salt
}
