// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newCmdMulticast() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "multicast",
		Short: "Manage multicast groups",
	}
	cmd.AddCommand(
		newCmdMulticastViewall(),
	)
	return cmd
}

func newCmdMulticastViewall() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "viewall",
		Short: "Run cilium-dbg bpf multicast group list on all Cilium agent pods",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, _ := signal.NotifyContext(cmd.Context(), os.Interrupt)
			ciliumPods, err := k8sClient.ListPods(ctx, namespace, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
			if err != nil {
				return err
			}
			for _, pod := range ciliumPods.Items {
				output, err := k8sClient.ExecInPod(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, []string{"cilium-dbg", "bpf", "multicast", "group", "list"})
				if err != nil {
					return err
				}
				fmt.Printf("Output from %s:\n%s\n", pod.Name, output.String())
			}
			return nil
		},
	}
	return cmd

}
