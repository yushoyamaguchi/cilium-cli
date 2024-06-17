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
		return "", err
	}
	return output.String(), nil
}

// ListGroup lists multicast groups in every node
func (m *Multicast) ListGroup() error {
	ctx, cancel := context.WithTimeout(context.Background(), m.params.WaitDuration)
	defer cancel()

	ciliumPods, err := m.listCiliumPods(ctx)
	if err != nil {
		return err
	}

	for _, ciliumPod := range ciliumPods {
		//Print cilium pod info
		_, err := m.printCiliumPodInfo(ciliumPod)
		if err != nil {
			return err
		}

		//List multicast groups
		cmd := []string{"cilium-dbg", "bpf", "multicast", "group", "list"}
		output, err := m.execInCiliumPod(ctx, ciliumPod, cmd)
		if err != nil {
			fmt.Fprintf(m.params.Writer, "\n")
			continue
		}
		fmt.Fprintln(m.params.Writer, output)
	}

	return nil
}

// ListSubscriber lists multicast subscribers in every node for the specified multicast group or all multicast groups
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
		//Print cilium pod info
		_, err := m.printCiliumPodInfo(ciliumPod)
		if err != nil {
			return err
		}

		//List multicast subscribers
		cmd := []string{"cilium-dbg", "bpf", "multicast", "subscriber", "list", target}
		output, err := m.execInCiliumPod(ctx, ciliumPod, cmd)
		if err != nil {
			fmt.Fprintf(m.params.Writer, "\n")
			continue
		}
		fmt.Fprintln(m.params.Writer, output)
	}

	return nil
}

// AddAllNodes add CiliumInternalIPs of all nodes to the specified multicast group as subscribers in every cilium-agent
func (m *Multicast) AddAllNodes() error {
	if m.params.MulticastGroupIP == "" {
		return fmt.Errorf("group-ip must be specified")
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.params.WaitDuration)
	defer cancel()
	ciliumPods, err := m.listCiliumPods(ctx)
	if err != nil {
		return err
	}

	//Create a map of ciliumInternalIPs of all nodes
	ipToPodMap := make(map[v2.NodeAddress]string)
	for _, ciliumPod := range ciliumPods {
		ciliumInternalIP, err := m.getCiliumInternalIP(ciliumPod.Spec.NodeName)
		if err != nil {
			return err
		}
		ipToPodMap[ciliumInternalIP] = ciliumPod.Name
	}

	for _, ciliumPod := range ciliumPods {
		//Print cilium pod info
		_, err := m.printCiliumPodInfo(ciliumPod)
		if err != nil {
			return err
		}

		//If there are not specified multicast group, create it
		cmd := []string{"cilium-dbg", "bpf", "multicast", "subscriber", "list", m.params.MulticastGroupIP}
		_, err = m.execInCiliumPod(ctx, ciliumPod, cmd)
		if err != nil {
			cmd = []string{"cilium-dbg", "bpf", "multicast", "group", "add", m.params.MulticastGroupIP}
			_, err := m.execInCiliumPod(ctx, ciliumPod, cmd)
			if err != nil {
				fmt.Fprintf(m.params.Writer, "Unable to create multicast group %s in %s\n", m.params.MulticastGroupIP, ciliumPod.Name)
				continue
			}
		}

		//Add all ciliumInternalIPs of all nodes to the multicast group as subscribers
		cnt := 0
		for ip, podName := range ipToPodMap {
			if ip.IP != "" && ciliumPod.Name != podName {
				cmd = []string{"cilium-dbg", "bpf", "multicast", "subscriber", "add", m.params.MulticastGroupIP, ip.IP}
				_, err := m.execInCiliumPod(ctx, ciliumPod, cmd)
				if err == nil {
					cnt++
				}
			}
		}
		fmt.Fprintf(m.params.Writer, "Added %d subscribers to multicast group %s\n\n", cnt, m.params.MulticastGroupIP)
	}

	return nil
}

// DelAllNodes delete CiliumInternalIPs of all nodes from the specified multicast group's subscribers in every cilium-agent
func (m *Multicast) DelAllNodes() error {
	if m.params.MulticastGroupIP == "" {
		return fmt.Errorf("group-ip must be specified")
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.params.WaitDuration)
	defer cancel()
	ciliumPods, err := m.listCiliumPods(ctx)
	if err != nil {
		return err
	}

	//Create a map of ciliumInternalIPs of all nodes
	ipToPodMap := make(map[v2.NodeAddress]string)
	for _, ciliumPod := range ciliumPods {
		ciliumInternalIP, err := m.getCiliumInternalIP(ciliumPod.Spec.NodeName)
		if err != nil {
			return err
		}
		ipToPodMap[ciliumInternalIP] = ciliumPod.Name
	}

	for _, ciliumPod := range ciliumPods {
		//Print cilium pod info
		_, err := m.printCiliumPodInfo(ciliumPod)
		if err != nil {
			return err
		}

		//If there are not specified multicast group, continue
		cmd := []string{"cilium-dbg", "bpf", "multicast", "subscriber", "list", m.params.MulticastGroupIP}
		output, err := m.execInCiliumPod(ctx, ciliumPod, cmd)
		if err != nil && output == "" {
			fmt.Fprintf(m.params.Writer, "Unable to find multicast group %s in %s\n", m.params.MulticastGroupIP, ciliumPod.Name)
			continue
		}

		//Delete all ciliumInternalIPs of all nodes from the multicast group's 'subscribers
		cnt := 0
		for ip, podName := range ipToPodMap {
			if ip.IP != "" && ciliumPod.Name != podName {
				cmd = []string{"cilium-dbg", "bpf", "multicast", "subscriber", "del", m.params.MulticastGroupIP, ip.IP}
				_, err := m.execInCiliumPod(ctx, ciliumPod, cmd)
				if err == nil {
					cnt++
				}
			}
		}
		fmt.Fprintf(m.params.Writer, "Deleted %d subscribers to multicast group %s\n\n", cnt, m.params.MulticastGroupIP)

		//Delete the multicast group
		cmd = []string{"cilium-dbg", "bpf", "multicast", "group", "delete", m.params.MulticastGroupIP}
		_, err = m.execInCiliumPod(ctx, ciliumPod, cmd)
		if err != nil {
			fmt.Fprintf(m.params.Writer, "Unable to delete multicast group %s in %s\n", m.params.MulticastGroupIP, ciliumPod.Name)
			continue
		} else {
			fmt.Fprintf(m.params.Writer, "Deleted multicast group %s in %s\n", m.params.MulticastGroupIP, ciliumPod.Name)
		}
	}

	return nil
}
