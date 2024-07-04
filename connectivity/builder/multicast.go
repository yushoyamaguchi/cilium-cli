// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

type multicastTest struct{}

func (t multicastTest) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("multicast", ct).
		WithScenarios(tests.MulticastTest())
}
