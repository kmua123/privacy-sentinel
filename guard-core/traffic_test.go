package guardcore

import (
	"encoding/json"
	"net"
	"reflect"
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

func readTraffic(t *testing.T) trafficSnapshot {
	t.Helper()
	var value trafficSnapshot
	if err := json.Unmarshal([]byte(TrafficSnapshot()), &value); err != nil {
		t.Fatalf("invalid traffic snapshot: %v", err)
	}
	if len(value.UIDs) != len(value.RXBytes) || len(value.UIDs) != len(value.TXBytes) {
		t.Fatal("unaligned per-UID counters")
	}
	return value
}

func TestTrafficSnapshotAccountsLiveClosedTCPAndUDP(t *testing.T) {
	beginTrafficSession()
	t.Cleanup(endTrafficSession)
	manager := statistic.DefaultManager
	tcp := statistic.NewTCPTracker(&trafficTestConn{}, manager, &C.Metadata{Uid: 10042}, nil, 3, 2, true)
	if _, err := tcp.Write([]byte("upload")); err != nil {
		t.Fatal(err)
	}
	if _, err := tcp.Read(make([]byte, 20)); err != nil {
		t.Fatal(err)
	}
	// Mihomo's accelerated copies use count callbacks instead of Read/Write.
	_, readers := tcp.UnwrapReader()
	_, writers := tcp.UnwrapWriter()
	readers[0](11)
	writers[0](13)
	udp := statistic.NewUDPTracker(&trafficTestPacketConn{}, manager, &C.Metadata{Uid: 10007}, nil, 0, 0, true)
	if _, err := udp.WriteTo([]byte("packet"), &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := udp.ReadFrom(make([]byte, 20)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := udp.WaitReadFrom(); err != nil {
		t.Fatal(err)
	}
	before := readTraffic(t)
	if before.State != "running" || before.Epoch <= 0 || !reflect.DeepEqual(before.UIDs, []uint32{10007, 10042}) {
		t.Fatalf("unexpected active snapshot: %+v", before)
	}
	if !reflect.DeepEqual(before.TXBytes, []int64{6, 22}) || !reflect.DeepEqual(before.RXBytes, []int64{10, 18}) {
		t.Fatalf("upload/download direction or initial/fast-path accounting wrong: %+v", before)
	}
	_ = tcp.Close()
	_ = tcp.Close()
	_ = udp.Close()
	if after := readTraffic(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("closing flows counted bytes again: before=%+v after=%+v", before, after)
	}
}

func TestTrafficEpochIsolatesLateTrackersAndNestedProxyTraffic(t *testing.T) {
	beginTrafficSession()
	t.Cleanup(endTrafficSession)
	old := statistic.NewTCPTracker(&trafficTestConn{}, statistic.DefaultManager, &C.Metadata{Uid: 10042}, nil, 7, 0, true)
	oldEpoch := readTraffic(t).Epoch
	endTrafficSession()
	stopped := readTraffic(t)
	if stopped.State != "stopped" || stopped.Epoch != oldEpoch || len(stopped.UIDs) != 0 {
		t.Fatalf("unexpected stopped snapshot: %+v", stopped)
	}
	beginTrafficSession()
	if readTraffic(t).Epoch <= oldEpoch {
		t.Fatal("core restart reused an epoch")
	}
	_, _ = old.Write([]byte("late old-session upload"))
	_ = old.Close()
	nested := statistic.NewTCPTracker(&trafficTestConn{}, statistic.DefaultManager, &C.Metadata{Uid: 10099}, nil, 77, 88, false)
	_, _ = nested.Write([]byte("nested proxy overhead"))
	_ = nested.Close()
	if current := readTraffic(t); len(current.UIDs) != 0 {
		t.Fatalf("late or nested traffic leaked into fresh session: %+v", current)
	}
	current := statistic.NewTCPTracker(&trafficTestConn{}, statistic.DefaultManager, &C.Metadata{Uid: 10043}, nil, 9, 0, true)
	_ = current.Close()
	if snapshot := readTraffic(t); !reflect.DeepEqual(snapshot.UIDs, []uint32{10043}) || snapshot.TXBytes[0] != 9 {
		t.Fatalf("new session lost its own traffic: %+v", snapshot)
	}
}

func TestTrafficSnapshotConcurrentUpdatesAndBoundedUIDs(t *testing.T) {
	beginTrafficSession()
	t.Cleanup(endTrafficSession)
	session := activeTrafficSession.Load()
	const workers, writes = 32, 1000
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Go(func() {
			for iteration := 0; iteration < writes; iteration++ {
				session.addUIDTraffic(10042, 3, 5)
			}
		})
	}
	for iteration := 0; iteration < 100; iteration++ {
		_ = readTraffic(t)
	}
	wait.Wait()
	snapshot := readTraffic(t)
	if snapshot.TXBytes[0] != workers*writes*3 || snapshot.RXBytes[0] != workers*writes*5 {
		t.Fatalf("concurrent increments lost: %+v", snapshot)
	}
	for uid := uint32(0); uid < maxTrafficUIDs+1; uid++ {
		session.addUIDTraffic(uid, 1, 0)
	}
	if got := len(readTraffic(t).UIDs); got != maxTrafficUIDs {
		t.Fatalf("UID bound not enforced: %d", got)
	}
}

func TestTrafficSnapshotOnlyExposesUIDCounters(t *testing.T) {
	beginTrafficSession()
	t.Cleanup(endTrafficSession)
	session := activeTrafficSession.Load()
	session.addUIDTraffic(10042, -7, 0)
	if len(readTraffic(t).UIDs) != 0 {
		t.Fatal("nonpositive increments created a counter")
	}
	session.addUIDTraffic(10042, 12, 34)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(TrafficSnapshot()), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 5 || fields["state"] == nil || fields["epoch"] == nil || fields["uids"] == nil || fields["rxBytes"] == nil || fields["txBytes"] == nil {
		t.Fatalf("snapshot exposed fields beyond state/epoch/UID counters: %v", fields)
	}
}

type trafficTestConn struct{ C.Conn }

func (*trafficTestConn) Read(p []byte) (int, error)  { return copy(p, "reply"), nil }
func (*trafficTestConn) Write(p []byte) (int, error) { return len(p), nil }
func (*trafficTestConn) Close() error                { return nil }
func (*trafficTestConn) RemoteDestination() string   { return "192.0.2.1:443" }
func (*trafficTestConn) Chains() C.Chain             { return nil }
func (*trafficTestConn) ProviderChains() C.Chain     { return nil }

type trafficTestPacketConn struct{ C.PacketConn }

func (*trafficTestPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return copy(p, "reply"), &net.UDPAddr{}, nil
}
func (*trafficTestPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return []byte("reply"), func() {}, &net.UDPAddr{}, nil
}
func (*trafficTestPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (*trafficTestPacketConn) Close() error                              { return nil }
func (*trafficTestPacketConn) RemoteDestination() string                 { return "192.0.2.2:443" }
func (*trafficTestPacketConn) Chains() C.Chain                           { return nil }
func (*trafficTestPacketConn) ProviderChains() C.Chain                   { return nil }
