// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multicast

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/node/addressing"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Multicast struct {
	client *k8s.Client
	params Parameters
}

type Parameters struct {
	CiliumNamespace  string
	Writer           io.Writer
	WaitDuration     time.Duration
	MulticastGroupIP string
	All              bool
}

func NewMulticast(client *k8s.Client, p Parameters) *Multicast {
	return &Multicast{
		client: client,
		params: p,
	}
}

func (m *Multicast) getCiliumInternalIP(nodeName string) (v2.NodeAddress, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.params.WaitDuration)
	defer cancel()
	ciliumNodes, err := m.client.ListCiliumNodes(ctx)
	if err != nil {
		return v2.NodeAddress{}, err
	}
	var ciliumNode v2.CiliumNode
	for _, node := range ciliumNodes.Items {
		if node.Name == nodeName {
			ciliumNode = node
		}
	}
	addrs := ciliumNode.Spec.Addresses
	var ciliumInternalIP v2.NodeAddress
	for _, addr := range addrs {
		if addr.AddrType() == addressing.NodeCiliumInternalIP {
			ip := net.ParseIP(addr.IP)
			if ip != nil && ip.To4() != nil {
				ciliumInternalIP = addr
			}
		}
	}
	return ciliumInternalIP, nil
}

func (m *Multicast) listCiliumPods(ctx context.Context) ([]corev1.Pod, error) {
	ciliumPods, err := m.client.ListPods(ctx, m.params.CiliumNamespace, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
	if err != nil {
		return nil, fmt.Errorf("unable to list Cilium pods: %w", err)
	}
	return ciliumPods.Items, nil
}

func (m *Multicast) printCiliumPodInfo(ciliumPod corev1.Pod) (string, error) {
	ciliumInternalIP, err := m.getCiliumInternalIP(ciliumPod.Spec.NodeName)
	if err != nil {
		return "", fmt.Errorf("unable to get ciliumInternalIP: %w", err)
	}
	info := fmt.Sprintf("Node: %s, cilium pod: %s, ciliumInternalIP: %s", ciliumPod.Spec.NodeName, ciliumPod.Name, ciliumInternalIP.IP)
	fmt.Fprintln(m.params.Writer, info)
	return ciliumInternalIP.IP, nil
}

func (m *Multicast) execInCiliumPod(ctx context.Context, ciliumPod corev1.Pod, command []string) (string, error) {
	output, err := m.client.ExecInPod(ctx, ciliumPod.Namespace, ciliumPod.Name, defaults.AgentContainerName, command)
	if err != nil {
		return "", nil // even if there is no output, we should return nil error
	}
	return output.String(), nil
}

func (m *Multicast) ListGroup() error {
	ctx, cancel := context.WithTimeout(context.Background(), m.params.WaitDuration)
	defer cancel()

	ciliumPods, err := m.listCiliumPods(ctx)
	if err != nil {
		return err
	}

	for _, ciliumPod := range ciliumPods {
		_, err := m.printCiliumPodInfo(ciliumPod)
		if err != nil {
			return err
		}

		output, err := m.execInCiliumPod(ctx, ciliumPod, []string{"cilium-dbg", "bpf", "multicast", "group", "list"})
		if err != nil {
			return err
		}
		fmt.Fprintln(m.params.Writer, output)
	}

	return nil
}

func (m *Multicast) ListSubscriber() error {
	if m.params.MulticastGroupIP == "" && !m.params.All {
		return fmt.Errorf("group-ip or all flag must be specified")
	} else if m.params.MulticastGroupIP != "" && m.params.All {
		return fmt.Errorf("only one of group-ip or all flag must be specified")
	}

	var target string
	if m.params.All {
		target = "all"
	} else {
		target = m.params.MulticastGroupIP
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.params.WaitDuration)
	defer cancel()

	ciliumPods, err := m.listCiliumPods(ctx)
	if err != nil {
		return err
	}

	for _, ciliumPod := range ciliumPods {
		_, err := m.printCiliumPodInfo(ciliumPod)
		if err != nil {
			return err
		}

		output, err := m.execInCiliumPod(ctx, ciliumPod, []string{"cilium-dbg", "bpf", "multicast", "subscriber", "list", target})
		if err != nil {
			return err
		}
		fmt.Fprintln(m.params.Writer, output)
	}

	return nil
}
