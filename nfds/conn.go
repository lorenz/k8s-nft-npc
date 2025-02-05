package nfds

import "github.com/google/nftables"

type Conn struct {
	c *nftables.Conn
}

func WrapConn(c *nftables.Conn) *Conn {
	return &Conn{c: c}
}

func (c *Conn) Flush() error {
	return c.c.Flush()
}

func (c *Conn) CloseLasting() error {
	return c.c.CloseLasting()
}
