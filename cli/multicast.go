// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"os"
	"time"

	"github.com/cilium/cilium-cli/multicast"
	"github.com/spf13/cobra"
)

func newCmdMulticast() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "multicast",
		Short: "Manage multicast groups",
		Long:  ``,
	}
	cmd.AddCommand(
		newCmdMulticastList(),
	)
	return cmd
}

func newCmdMulticastList() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show list of somthing about multicast",
		Long:  ``,
	}

	cmd.AddCommand(
		newCmdMulticastListGroup(),
		newCmdMulticastListSubscriber(),
	)
	return cmd

}

func newCmdMulticastListGroup() *cobra.Command {
	var params = multicast.Parameters{
		Writer: os.Stdout,
	}
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Show list of multicast groups in every node",
		RunE: func(cmd *cobra.Command, args []string) error {
			params.CiliumNamespace = namespace
			mc := multicast.NewMulticast(k8sClient, params)
			err := mc.ListGroup()
			if err != nil {
				fatalf("Unable to list multicast groups: %s", err)
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 1*time.Minute, "Maximum time to wait for result, default 1 minute")
	return cmd

}

func newCmdMulticastListSubscriber() *cobra.Command {
	var params = multicast.Parameters{
		Writer: os.Stdout,
	}
	cmd := &cobra.Command{
		Use:   "subscriber",
		Short: "Show list of subscribers belonging to the specified multicast group",
		RunE: func(cmd *cobra.Command, args []string) error {
			params.CiliumNamespace = namespace
			mc := multicast.NewMulticast(k8sClient, params)
			err := mc.ListSubscriber()
			if err != nil {
				fatalf("Unable to list subscribers of the multicast group: %s", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.MulticastGroupIP, "group-ip", "g", "", "Multicast group IP address")
	cmd.Flags().BoolVar(&params.All, "all", false, "Show all subscribers")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 1*time.Minute, "Maximum time to wait for result, default 1 minute")
	return cmd

}
