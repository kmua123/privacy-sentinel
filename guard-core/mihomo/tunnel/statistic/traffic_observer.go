package statistic

import "sync"

var trafficObserver struct {
	sync.RWMutex
	callback func(uid uint32, uploaded, downloaded int64)
}

// SetTrafficObserver installs a native-only incremental accounting observer.
// Original forwarding trackers capture it when they are created. Nested proxy
// and DNS trackers (pushToManager=false) are excluded to avoid double counting.
// Capturing the callback keeps late bytes on an old session after a core reset.
func SetTrafficObserver(callback func(uid uint32, uploaded, downloaded int64)) {
	trafficObserver.Lock()
	trafficObserver.callback = callback
	trafficObserver.Unlock()
}

func (info *TrackerInfo) initializeTraffic(uploaded, downloaded int64, original bool) {
	if !original || info.Metadata == nil {
		return
	}
	trafficObserver.RLock()
	info.trafficCallback = trafficObserver.callback
	trafficObserver.RUnlock()
	info.trafficUID = info.Metadata.Uid
	info.addTraffic(uploaded, downloaded)
}

func (info *TrackerInfo) addTraffic(uploaded, downloaded int64) {
	if info.trafficCallback != nil && (uploaded > 0 || downloaded > 0) {
		if uploaded < 0 {
			uploaded = 0
		}
		if downloaded < 0 {
			downloaded = 0
		}
		info.trafficCallback(info.trafficUID, uploaded, downloaded)
	}
}
