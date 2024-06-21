// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multicast

import (
	"context"
	"fmt"
	"io"
	"net/netip"
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

func (m *Multicast) getCiliumNode(ctx context.Context, nodeName string) (v2.CiliumNode, error) {
	ciliumNodes, err := m.client.ListCiliumNodes(ctx)
	if err != nil {
		return v2.CiliumNode{}, err
	}
	var ciliumNode v2.CiliumNode
	for _, node := range ciliumNodes.Items {
		if node.Name == nodeName {
			ciliumNode = node
		}
	}
	return ciliumNode, nil
}

func (m *Multicast) getCiliumInternalIP(nodeName string) (v2.NodeAddress, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.params.WaitDuration)
	defer cancel()
	ciliumNode, err := m.getCiliumNode(ctx, nodeName)
	if err != nil {
		return v2.NodeAddress{}, fmt.Errorf("unable to get cilium node: %w", err)
	}
	addrs := ciliumNode.Spec.Addresses
	var ciliumInternalIP v2.NodeAddress
	for _, addr := range addrs {
		if addr.AddrType() == addressing.NodeCiliumInternalIP {
			ip, err := netip.ParseAddr(addr.IP)
			if err != nil {
				continue
			}
			if ip.Is4() {
				ciliumInternalIP = addr
			}
		}
	}
	if ciliumInternalIP.IP == "" {
		return v2.NodeAddress{}, fmt.Errorf("ciliumInternalIP not found")
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
		fmt.Fprintf(m.params.Writer, "Node: %s\n", ciliumPod.Spec.NodeName)

		//List multicast groups
		cmd := []string{"cilium-dbg", "bpf", "multicast", "group", "list"}
		output, err := m.client.ExecInPod(ctx, ciliumPod.Namespace, ciliumPod.Name, defaults.AgentContainerName, cmd)
		if err != nil {
			return err
		}
		fmt.Fprintln(m.params.Writer, output.String())
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
		fmt.Fprintf(m.params.Writer, "Node: %s\n", ciliumPod.Spec.NodeName)

		//List multicast subscribers
		cmd := []string{"cilium-dbg", "bpf", "multicast", "subscriber", "list", target}
		output, err := m.client.ExecInPod(ctx, ciliumPod.Namespace, ciliumPod.Name, defaults.AgentContainerName, cmd)
		if err != nil {
			return err
		}
		fmt.Fprintln(m.params.Writer, output.String())
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
	ipToNodeMap := make(map[v2.NodeAddress]string)
	for _, ciliumPod := range ciliumPods {
		ciliumInternalIP, err := m.getCiliumInternalIP(ciliumPod.Spec.NodeName)
		if err != nil {
			return err
		}
		ipToPodMap[ciliumInternalIP] = ciliumPod.Name
		ipToNodeMap[ciliumInternalIP] = ciliumPod.Spec.NodeName
	}

	for _, ciliumPod := range ciliumPods {
		//If there are not specified multicast group, create it
		cmd := []string{"cilium-dbg", "bpf", "multicast", "subscriber", "list", m.params.MulticastGroupIP}
		_, err = m.client.ExecInPod(ctx, ciliumPod.Namespace, ciliumPod.Name, defaults.AgentContainerName, cmd)
		if err != nil {
			cmd = []string{"cilium-dbg", "bpf", "multicast", "group", "add", m.params.MulticastGroupIP}
			_, err := m.client.ExecInPod(ctx, ciliumPod.Namespace, ciliumPod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				fmt.Fprintf(m.params.Writer, "Unable to create multicast group %s in %s\n", m.params.MulticastGroupIP, ciliumPod.Name)
				continue
			}
		}

		//Add all ciliumInternalIPs of all nodes to the multicast group as subscribers
		cnt := 0
		var nodeLists []string
		for ip, podName := range ipToPodMap {
			if ip.IP != "" && ciliumPod.Name != podName { //My node itself does not need to be in a multicast group.
				cmd = []string{"cilium-dbg", "bpf", "multicast", "subscriber", "add", m.params.MulticastGroupIP, ip.IP}
				_, err := m.client.ExecInPod(ctx, ciliumPod.Namespace, ciliumPod.Name, defaults.AgentContainerName, cmd)
				if err == nil {
					cnt++
					nodeLists = append(nodeLists, ipToNodeMap[ip])
				}
			}
		}
		if cnt == 0 {
			fmt.Fprintf(m.params.Writer, "Unable to add any node to multicast group %s in %s\n", m.params.MulticastGroupIP, ciliumPod.Spec.NodeName)
			continue
		} else if cnt == 1 {
			fmt.Fprintf(m.params.Writer, "Added a node (")
		} else {
			fmt.Fprintf(m.params.Writer, "Added %d nodes (", cnt)
		}
		for i, node := range nodeLists {
			if i == len(nodeLists)-1 {
				fmt.Fprintf(m.params.Writer, "%s", node)
			} else {
				fmt.Fprintf(m.params.Writer, "%s, ", node)
			}
		}
		fmt.Fprintf(m.params.Writer, ") to multicast group %s in %s\n", m.params.MulticastGroupIP, ciliumPod.Spec.NodeName)
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
	ipToNodeMap := make(map[v2.NodeAddress]string)
	for _, ciliumPod := range ciliumPods {
		ciliumInternalIP, err := m.getCiliumInternalIP(ciliumPod.Spec.NodeName)
		if err != nil {
			return err
		}
		ipToPodMap[ciliumInternalIP] = ciliumPod.Name
		ipToNodeMap[ciliumInternalIP] = ciliumPod.Spec.NodeName
	}

	for _, ciliumPod := range ciliumPods {
		//Delete the multicast group
		cmd := []string{"cilium-dbg", "bpf", "multicast", "group", "delete", m.params.MulticastGroupIP}
		_, err = m.client.ExecInPod(ctx, ciliumPod.Namespace, ciliumPod.Name, defaults.AgentContainerName, cmd)
		if err != nil {
			fmt.Fprintf(m.params.Writer, "Unable to delete multicast group %s in %s\n", m.params.MulticastGroupIP, ciliumPod.Spec.NodeName)
			continue
		} else {
			fmt.Fprintf(m.params.Writer, "Deleted multicast group %s in %s\n", m.params.MulticastGroupIP, ciliumPod.Spec.NodeName)
		}
	}

	return nil
}
