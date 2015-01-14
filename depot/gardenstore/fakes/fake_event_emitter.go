// This file was generated by counterfeiter
package fakes

import (
	"sync"

	"github.com/cloudfoundry-incubator/executor"
	"github.com/cloudfoundry-incubator/executor/depot/gardenstore"
)

type FakeEventEmitter struct {
	EmitEventStub        func(executor.Event)
	emitEventMutex       sync.RWMutex
	emitEventArgsForCall []struct {
		arg1 executor.Event
	}
}

func (fake *FakeEventEmitter) EmitEvent(arg1 executor.Event) {
	fake.emitEventMutex.Lock()
	fake.emitEventArgsForCall = append(fake.emitEventArgsForCall, struct {
		arg1 executor.Event
	}{arg1})
	fake.emitEventMutex.Unlock()
	if fake.EmitEventStub != nil {
		fake.EmitEventStub(arg1)
	}
}

func (fake *FakeEventEmitter) EmitEventCallCount() int {
	fake.emitEventMutex.RLock()
	defer fake.emitEventMutex.RUnlock()
	return len(fake.emitEventArgsForCall)
}

func (fake *FakeEventEmitter) EmitEventArgsForCall(i int) executor.Event {
	fake.emitEventMutex.RLock()
	defer fake.emitEventMutex.RUnlock()
	return fake.emitEventArgsForCall[i].arg1
}

var _ gardenstore.EventEmitter = new(FakeEventEmitter)