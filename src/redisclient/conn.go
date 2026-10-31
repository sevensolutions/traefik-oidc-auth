package redisclient

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

// conn wraps a single, already-authenticated TCP (or TLS) connection to Redis, framed for RESP2.
type conn struct {
	nc  net.Conn
	r   *bufio.Reader
	w   *bufio.Writer
	cfg Config
}

func dial(cfg Config) (*conn, error) {
	dialer := &net.Dialer{Timeout: cfg.DialTimeout}

	var nc net.Conn
	var err error

	if cfg.UseTLS {
		tlsConfig := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}
		nc, err = tls.DialWithDialer(dialer, "tcp", cfg.Address, tlsConfig)
	} else {
		nc, err = dialer.Dial("tcp", cfg.Address)
	}
	if err != nil {
		return nil, fmt.Errorf("redis: failed to connect to %s: %w", cfg.Address, err)
	}

	c := &conn{
		nc:  nc,
		r:   bufio.NewReader(nc),
		w:   bufio.NewWriter(nc),
		cfg: cfg,
	}

	if err := c.authenticate(); err != nil {
		nc.Close()
		return nil, err
	}

	if cfg.Database != 0 {
		if _, err := c.do("SELECT", strconv.Itoa(cfg.Database)); err != nil {
			nc.Close()
			return nil, fmt.Errorf("redis: SELECT %d failed: %w", cfg.Database, err)
		}
	}

	return c, nil
}

func (c *conn) authenticate() error {
	if c.cfg.Password == "" {
		return nil
	}

	var err error
	if c.cfg.Username != "" {
		_, err = c.do("AUTH", c.cfg.Username, c.cfg.Password)
	} else {
		_, err = c.do("AUTH", c.cfg.Password)
	}
	if err != nil {
		return fmt.Errorf("redis: AUTH failed: %w", err)
	}
	return nil
}

// do sends a command and returns its decoded reply. A RESP error reply is surfaced as a Go error.
func (c *conn) do(args ...string) (reply, error) {
	if err := c.setDeadline(); err != nil {
		return reply{}, err
	}
	if err := writeCommand(c.w, args...); err != nil {
		return reply{}, err
	}
	r, err := readReply(c.r)
	if err != nil {
		return reply{}, err
	}
	if r.isErr {
		return reply{}, fmt.Errorf("redis: %s", r.str)
	}
	return r, nil
}

func (c *conn) setDeadline() error {
	timeout := c.cfg.ReadTimeout
	if c.cfg.WriteTimeout > timeout {
		timeout = c.cfg.WriteTimeout
	}
	if timeout <= 0 {
		return nil
	}
	return c.nc.SetDeadline(time.Now().Add(timeout))
}

func (c *conn) close() {
	_ = c.nc.Close()
}
