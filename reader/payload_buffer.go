package reader

import (
	"context"
	"sync"
	"time"

	"github.com/k1LoW/tcpdp/dumper"
	"go.uber.org/zap"
)

type payloadBuffer struct {
	srcToDst []byte
	dstToSrc []byte
	unknown  []byte
	expires  time.Time
	// created  time.Time
}

func newPayloadBuffer() *payloadBuffer {
	p := payloadBuffer{
		// created: time.Now()
	}
	p.updateExpires()
	return &p
}

func (p *payloadBuffer) updateExpires() {
	if p == nil {
		return
	}
	p.expires = time.Now().Add(time.Duration(packetTTL) * time.Second)
}

func (p *payloadBuffer) Expired() bool {
	if p == nil {
		return true
	}
	return p.expires.Before(time.Now())
}

func (p *payloadBuffer) Get(direction dumper.Direction) []byte {
	if p == nil {
		return nil
	}
	switch direction {
	case dumper.SrcToDst:
		if len(p.srcToDst) > 0 {
			p.updateExpires()
		}
		return p.srcToDst
	case dumper.DstToSrc:
		if len(p.dstToSrc) > 0 {
			p.updateExpires()
		}
		return p.dstToSrc
	case dumper.Unknown:
		if len(p.unknown) > 0 {
			p.updateExpires()
		}
		return p.unknown
	}
	return nil
}

func (p *payloadBuffer) Delete(direction dumper.Direction) {
	p.updateExpires()
	switch direction {
	case dumper.SrcToDst:
		p.srcToDst = nil
	case dumper.DstToSrc:
		p.dstToSrc = nil
	case dumper.Unknown:
		p.unknown = nil
	}
}

func (p *payloadBuffer) Append(direction dumper.Direction, in []byte) {
	p.updateExpires()
	switch direction {
	case dumper.SrcToDst:
		p.srcToDst = append(p.srcToDst, in...)
	case dumper.DstToSrc:
		p.dstToSrc = append(p.dstToSrc, in...)
	case dumper.Unknown:
		p.unknown = append(p.unknown, in...)
	}
}

func (p *payloadBuffer) Size() int {
	return len(p.srcToDst) + len(p.dstToSrc) + len(p.unknown)
}

type payloadBufferManager struct {
	buffers map[string]*payloadBuffer
	mutex   *sync.Mutex
}

func newPayloadBufferManager() *payloadBufferManager {
	return &payloadBufferManager{
		buffers: map[string]*payloadBuffer{},
		mutex:   new(sync.Mutex),
	}
}

func (m *payloadBufferManager) lock() {
	m.mutex.Lock()
}

func (m *payloadBufferManager) unlock() {
	m.mutex.Unlock()
}

func (m *payloadBufferManager) newBuffer(key string, force bool) {
	m.lock()
	if _, ok := m.buffers[key]; !ok || force {
		m.buffers[key] = newPayloadBuffer()
	}
	m.unlock()
}

func (m *payloadBufferManager) Append(key string, direction dumper.Direction, in []byte) {
	m.lock()
	m.buffers[key].Append(direction, in)
	m.unlock()
}

func (m *payloadBufferManager) deleteBuffer(key string) {
	m.lock()
	delete(m.buffers, key)
	m.unlock()
}

func (m *payloadBufferManager) startPurgeTicker(ctx context.Context, logger *zap.Logger) {
	t := time.NewTicker(time.Duration(packetTTL/10) * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// purge expired packet buffer cache
			purgedSize := 0
			m.lock()
			for key, b := range m.buffers {
				bSize := b.Size()
				if b.Expired() || bSize == 0 {
					if bSize > 0 {
						purgedSize = purgedSize + bSize
					}
					delete(m.buffers, key)
				}
			}
			m.unlock()
			if purgedSize > 0 {
				logger.Info("purge expired packet buffer cache", zap.Int("purged_size", purgedSize))
			}
		}
	}
}
