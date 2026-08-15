package admission

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServerRejectsMalformedRequest(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	s := Server{MaxConnections: 1, ReadTimeout: time.Second, WriteTimeout: time.Second}
	go s.handle(context.Background(), server)
	if _, err := client.Write([]byte("request=wrong\n\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "action=REJECT 550") {
		t.Fatalf("response=%q", line)
	}
}
