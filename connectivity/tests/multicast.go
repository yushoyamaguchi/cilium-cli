// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"

	"github.com/cilium/cilium-cli/connectivity/check"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		ct := t.Context()
		client := ct.K8sClient()
		// get cilium agent pod name using k8s client
		ciliumPods, err := client.ListPods(ctx, "kube-system", metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
		if err != nil {
			return
		}
		for _, pod := range ciliumPods.Items {
			_, err := client.ExecInPod(ctx, pod.Namespace, pod.Name, "cilium-agent", []string{"cilium-dbg", "bpf", "multicast", "group", "add", "239.255.0.9"})
			if err != nil {
				a.Log("err")
			}
		}
		//a.PuseudoFail()
	})
}
