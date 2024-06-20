// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

type yamaTest1 struct{}

func (t yamaTest1) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("yama-test1", ct).
		WithScenarios(tests.PodToPodMulti())
}
