package guardcore

import (
	"encoding/json"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/tunnel/statistic"
)

const maxTrafficUIDs = 10_000

var activeTrafficSession atomic.Pointer[trafficSession]
var lastTrafficEpoch atomic.Int64

type trafficSession struct {
	epoch int64
	mu    sync.RWMutex
	uids  map[uint32]*uidTraffic
}

type uidTraffic struct {
	rx atomic.Int64
	tx atomic.Int64
}

type trafficSnapshot struct {
	State   string   `json:"state"`
	Epoch   int64    `json:"epoch"`
	UIDs    []uint32 `json:"uids"`
	RXBytes []int64  `json:"rxBytes"`
	TXBytes []int64  `json:"txBytes"`
}

// Called under the core lifecycle lock, before the new forwarding listener is
// exposed. A tracker captures this particular session, never the global pointer.
func beginTrafficSession() {
	var epoch int64
	for {
		previous := lastTrafficEpoch.Load()
		epoch = max(time.Now().UnixMilli(), previous+1)
		if lastTrafficEpoch.CompareAndSwap(previous, epoch) {
			break
		}
	}
	session := &trafficSession{epoch: epoch, uids: make(map[uint32]*uidTraffic)}
	activeTrafficSession.Store(session)
	statistic.SetTrafficObserver(session.addUIDTraffic)
}

func endTrafficSession() {
	statistic.SetTrafficObserver(nil)
	activeTrafficSession.Store(nil)
}

func (session *trafficSession) addUIDTraffic(uid uint32, uploaded, downloaded int64) {
	if uploaded <= 0 && downloaded <= 0 {
		return
	}
	session.mu.RLock()
	entry := session.uids[uid]
	session.mu.RUnlock()
	if entry == nil {
		session.mu.Lock()
		entry = session.uids[uid]
		if entry == nil && len(session.uids) < maxTrafficUIDs {
			entry = &uidTraffic{}
			session.uids[uid] = entry
		}
		session.mu.Unlock()
	}
	if entry == nil {
		return
	}
	if uploaded > 0 {
		entry.tx.Add(uploaded)
	}
	if downloaded > 0 {
		entry.rx.Add(downloaded)
	}
}

// TrafficSnapshot reports cumulative forwarded payload bytes observed by the
// active guarded VPN. It includes open and closed flows without settling either
// a second time. It is not the whole-device, carrier or radio byte counter.
// Epoch changes whenever Start creates a new core, so callers reset their delta
// baseline after a configuration reload. No endpoint, hostname or secret leaves
// the native core through this API. Per-UID arrays are aligned and sorted.
func TrafficSnapshot() string {
	value := trafficSnapshot{
		State: "stopped", Epoch: lastTrafficEpoch.Load(),
		UIDs: []uint32{}, RXBytes: []int64{}, TXBytes: []int64{},
	}
	if session := activeTrafficSession.Load(); session != nil {
		value.State = "running"
		value.Epoch = session.epoch
		session.mu.RLock()
		for uid := range session.uids {
			value.UIDs = append(value.UIDs, uid)
		}
		sort.Slice(value.UIDs, func(i, j int) bool { return value.UIDs[i] < value.UIDs[j] })
		for _, uid := range value.UIDs {
			entry := session.uids[uid]
			value.RXBytes = append(value.RXBytes, entry.rx.Load())
			value.TXBytes = append(value.TXBytes, entry.tx.Load())
		}
		session.mu.RUnlock()
	}
	data, _ := json.Marshal(value)
	return string(data)
}
