// Package redisclient is a minimal, pure-Go Redis client.
// This exists because traefik-oidc-auth runs inside Traefik via yaegi (a Go interpreter), which
// only supports pure-Go code built from its bundled stdlib symbol table - no cgo, no unsafe, etc.
// The official redis/go-redis client can't be interpreted by yaegi,
// so this package implements only the handful of commands session storage actually needs
// (SET, GET, DEL, AUTH, SELECT, PING) using nothing but net, crypto/tls, bufio, strconv and
// strings - packages already proven to work under yaegi elsewhere in this plugin.
package redisclient

import (
	"strconv"
	"time"
)

// Config configures a Pool of connections to a single Redis (or Redis-compatible) server.
// There is no Sentinel/Cluster support - just one Address.
type Config struct {
	Address  string
	Username string
	Password string
	Database int

	UseTLS             bool
	InsecureSkipVerify bool

	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// PoolSize is the max number of connections kept idle in the pool. Checkouts beyond this
	// still succeed - they just dial a fresh, unpooled connection.
	PoolSize int
}

// Pool is a small, self-healing pool of persistent RESP2 connections to a single Redis server.
// It dials lazily: no network I/O happens until the first command is issued, so constructing a
// Pool can never fail or block on Redis being unreachable.
type Pool struct {
	cfg   Config
	conns chan *conn
}

// NewPool constructs a Pool. It performs no network I/O.
func NewPool(cfg Config) *Pool {
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 1
	}
	return &Pool{
		cfg:   cfg,
		conns: make(chan *conn, cfg.PoolSize),
	}
}

// get checks out a pooled connection, or dials a new one if the pool is currently empty.
func (p *Pool) get() (*conn, error) {
	select {
	case c := <-p.conns:
		return c, nil
	default:
		return dial(p.cfg)
	}
}

// put returns a healthy connection to the pool, or closes it if it's unhealthy or the pool is
// already full. Never blocks.
func (p *Pool) put(c *conn, healthy bool) {
	if !healthy {
		c.close()
		return
	}

	select {
	case p.conns <- c:
	default:
		c.close()
	}
}

// withConn checks out a connection, runs fn, and returns the connection to the pool - or
// discards it, so a broken connection is never reused - based on whether fn succeeded.
func (p *Pool) withConn(fn func(c *conn) (reply, error)) (reply, error) {
	c, err := p.get()
	if err != nil {
		return reply{}, err
	}

	r, err := fn(c)
	p.put(c, err == nil)
	return r, err
}

// Set stores value under key. A positive ttl sets an expiration (SET ... EX <seconds>); a
// non-positive ttl stores the key with no expiration.
func (p *Pool) Set(key, value string, ttl time.Duration) error {
	args := []string{"SET", key, value}
	if ttl > 0 {
		args = append(args, "EX", strconv.Itoa(int(ttl.Seconds())))
	}

	_, err := p.withConn(func(c *conn) (reply, error) {
		return c.do(args...)
	})
	return err
}

// Get retrieves the value stored under key. found is false, with no error, if key doesn't exist.
func (p *Pool) Get(key string) (value string, found bool, err error) {
	r, err := p.withConn(func(c *conn) (reply, error) {
		return c.do("GET", key)
	})
	if err != nil {
		return "", false, err
	}
	if r.isNil {
		return "", false, nil
	}
	return r.str, true, nil
}

// Del removes key. It is not an error if key doesn't exist.
func (p *Pool) Del(key string) error {
	_, err := p.withConn(func(c *conn) (reply, error) {
		return c.do("DEL", key)
	})
	return err
}

// Ping checks connectivity to the Redis server, dialing a connection if needed.
func (p *Pool) Ping() error {
	_, err := p.withConn(func(c *conn) (reply, error) {
		return c.do("PING")
	})
	return err
}
