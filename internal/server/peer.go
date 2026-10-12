package server

import (
	"context"
	"net"
	"syscall"
)

type peerKey struct{}

// peer is the kernel-reported identity of the process on the other end of
// the unix socket. It cannot be forged by the client.
type peer struct {
	uid, pid int
	known    bool
}

// ConnContext records the peer credentials (SO_PEERCRED) of each unix
// connection; plug it into http.Server.ConnContext.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	p := peer{}
	if uc, ok := c.(*net.UnixConn); ok {
		if raw, err := uc.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				if cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err == nil { // #nosec G115 -- a file descriptor fits in an int
					p = peer{uid: int(cred.Uid), pid: int(cred.Pid), known: true}
				}
			})
		}
	}
	return context.WithValue(ctx, peerKey{}, p)
}

func peerOf(ctx context.Context) peer {
	p, _ := ctx.Value(peerKey{}).(peer)
	return p
}

// PeerUID returns the kernel-reported uid of the client of a request.
func PeerUID(ctx context.Context) (int, bool) {
	p := peerOf(ctx)
	return p.uid, p.known
}
