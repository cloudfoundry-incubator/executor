// This file was generated by counterfeiter
package fakeguidgen

import (
	"sync"

	"code.cloudfoundry.org/executor/guidgen"
	"code.cloudfoundry.org/lager"
)

type FakeGenerator struct {
	GuidStub        func(lager.Logger) string
	guidMutex       sync.RWMutex
	guidArgsForCall []struct {
		arg1 lager.Logger
	}
	guidReturns struct {
		result1 string
	}
}

func (fake *FakeGenerator) Guid(arg1 lager.Logger) string {
	fake.guidMutex.Lock()
	fake.guidArgsForCall = append(fake.guidArgsForCall, struct {
		arg1 lager.Logger
	}{arg1})
	fake.guidMutex.Unlock()
	if fake.GuidStub != nil {
		return fake.GuidStub(arg1)
	} else {
		return fake.guidReturns.result1
	}
}

func (fake *FakeGenerator) GuidCallCount() int {
	fake.guidMutex.RLock()
	defer fake.guidMutex.RUnlock()
	return len(fake.guidArgsForCall)
}

func (fake *FakeGenerator) GuidArgsForCall(i int) lager.Logger {
	fake.guidMutex.RLock()
	defer fake.guidMutex.RUnlock()
	return fake.guidArgsForCall[i].arg1
}

func (fake *FakeGenerator) GuidReturns(result1 string) {
	fake.GuidStub = nil
	fake.guidReturns = struct {
		result1 string
	}{result1}
}

var _ guidgen.Generator = new(FakeGenerator)
