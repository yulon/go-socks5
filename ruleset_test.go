package socks5

import (
	"testing"

	"golang.org/x/net/context"
)

func TestPermitCommand(t *testing.T) {
	ctx := context.Background()
	r := &PermitCommand{true, false, false}

	if _, ok := r.Allow(ctx, &Request{Command: CommandConnect}); !ok {
		t.Fatalf("expect connect")
	}

	if _, ok := r.Allow(ctx, &Request{Command: CommandBind}); ok {
		t.Fatalf("do not expect bind")
	}

	if _, ok := r.Allow(ctx, &Request{Command: CommandAssociate}); ok {
		t.Fatalf("do not expect associate")
	}
}
