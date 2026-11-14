package sing_tun

import (
	"context"
	"net"
	"net/netip"
	"sync"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

// IngressGuard is installed by the embedding application. It runs before DNS
// hijacking, sniffing, rule matching, or a proxy/direct/overlay connection.
type IngressGuard interface {
	TCP(context.Context, net.Conn, M.Metadata) (context.Context, net.Conn, error)
	Packet(context.Context, netip.AddrPort, M.Metadata) (context.Context, error)
	PacketConnection(context.Context, network.PacketConn, M.Metadata) (context.Context, network.PacketConn, error)
}

var ingressGuard struct {
	sync.RWMutex
	value IngressGuard
}

func SetIngressGuard(guard IngressGuard) {
	ingressGuard.Lock()
	ingressGuard.value = guard
	ingressGuard.Unlock()
}

func currentIngressGuard() IngressGuard {
	ingressGuard.RLock()
	defer ingressGuard.RUnlock()
	return ingressGuard.value
}
