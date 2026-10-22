package main

import (
	"context"
	"github.com/miekg/dns"
	"net"
	"time"
)

type wireTimes struct{ DialEnded, WriteStarted, WriteEnded time.Time }
type tracedConn struct {
	net.Conn
	times *wireTimes
}

func (c tracedConn) Write(b []byte) (int, error) {
	c.times.WriteStarted = time.Now()
	n, e := c.Conn.Write(b)
	c.times.WriteEnded = time.Now()
	return n, e
}

// Preserve PacketConn identity: miekg/dns uses it to select UDP framing.
type tracedUDP struct {
	*net.UDPConn
	times *wireTimes
}

func (c tracedUDP) Write(b []byte) (int, error) {
	c.times.WriteStarted = time.Now()
	n, e := c.UDPConn.Write(b)
	c.times.WriteEnded = time.Now()
	return n, e
}
func exchangeTraced(ctx context.Context, c *dns.Client, q *dns.Msg, address string, t *wireTimes) (*dns.Msg, error) {
	conn, err := c.DialContext(ctx, address)
	t.DialEnded = time.Now()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if udp, ok := conn.Conn.(*net.UDPConn); ok {
		conn.Conn = tracedUDP{udp, t}
	} else {
		conn.Conn = tracedConn{conn.Conn, t}
	}
	answer, _, err := c.ExchangeWithConnContext(ctx, q, conn)
	return answer, err
}
