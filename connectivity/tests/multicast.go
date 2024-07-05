// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"

	"github.com/cilium/cilium-cli/connectivity/check"
)

type multicastTest struct {
}

func MulticastTest() check.Scenario {
	return &multicastTest{}
}

func (s *multicastTest) Name() string {
	return "multicast"
}

func (s *multicastTest) Run(ctx context.Context, t *check.Test) {
	t.NewAction(s, "multicast", nil, nil, 0).Run(func(a *check.Action) {
		a.PuseudoFail()
	})
}
