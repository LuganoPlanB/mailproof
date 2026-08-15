package admission

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Server implements the small Postfix policy-protocol boundary. It deliberately
// has no access to mail bodies or analyzer dependencies.
type Server struct {
	Service        Service
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxConnections int
}

func (s Server) Serve(ctx context.Context, listener net.Listener) error {
	if s.MaxConnections < 1 {
		return errors.New("admission max connections must be positive")
	}
	if s.ReadTimeout <= 0 {
		s.ReadTimeout = 5 * time.Second
	}
	if s.WriteTimeout <= 0 {
		s.WriteTimeout = 5 * time.Second
	}
	sem := make(chan struct{}, s.MaxConnections)
	var wg sync.WaitGroup
	defer wg.Wait()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
			wg.Add(1)
			go func() { defer wg.Done(); defer func() { <-sem }(); s.handle(ctx, conn) }()
		default:
			_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
			_, _ = io.WriteString(conn, "action=DEFER_IF_PERMIT 450 4.7.1 admission service busy\n\n")
			_ = conn.Close()
		}
	}
}

func (s Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
	reader := bufio.NewReader(io.LimitReader(conn, 16<<10+1))
	var raw []byte
	for {
		line, err := reader.ReadBytes('\n')
		raw = append(raw, line...)
		if len(raw) > 16<<10 || err != nil && !errors.Is(err, io.EOF) {
			s.respond(conn, "action=DEFER_IF_PERMIT 450 4.7.1 malformed policy request")
			return
		}
		if len(line) == 1 || string(line) == "\r\n" {
			break
		}
		if errors.Is(err, io.EOF) {
			s.respond(conn, "action=DEFER_IF_PERMIT 450 4.7.1 malformed policy request")
			return
		}
	}
	r, err := ParseRequest(raw)
	if err != nil {
		s.respond(conn, "action=REJECT 550 5.7.1 invalid submission identity")
		return
	}
	d, err := s.Service.Admit(ctx, r)
	if errors.Is(err, ErrDeferred) {
		s.respond(conn, "action=DEFER_IF_PERMIT 450 4.7.1 admission temporarily unavailable")
		return
	}
	if errors.Is(err, ErrDenied) {
		s.respond(conn, "action=REJECT 550 5.7.1 submission rejected")
		return
	}
	s.respond(conn, "action=PREPEND X-Mailproof-Admission: "+d.Stamp)
}

func (s Server) respond(conn net.Conn, action string) {
	_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
	_, _ = io.WriteString(conn, action+"\n\n")
}
