// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Listeners in Oracle Cloud Infrastructure Network Load Balancer service.
//
// Lists all listeners associated with a given network load balancer.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := oci.GetNetworkLoadBalancerListeners(ctx, &GetNetworkLoadBalancerListenersArgs{
// 			NetworkLoadBalancerId: oci_network_load_balancer_network_load_balancer.Test_network_load_balancer.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetNetworkLoadBalancerListeners(ctx *pulumi.Context, args *GetNetworkLoadBalancerListenersArgs, opts ...pulumi.InvokeOption) (*GetNetworkLoadBalancerListenersResult, error) {
	var rv GetNetworkLoadBalancerListenersResult
	err := ctx.Invoke("oci:index/getNetworkLoadBalancerListeners:GetNetworkLoadBalancerListeners", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetNetworkLoadBalancerListeners.
type GetNetworkLoadBalancerListenersArgs struct {
	Filters []GetNetworkLoadBalancerListenersFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
	NetworkLoadBalancerId string `pulumi:"networkLoadBalancerId"`
}

// A collection of values returned by GetNetworkLoadBalancerListeners.
type GetNetworkLoadBalancerListenersResult struct {
	Filters []GetNetworkLoadBalancerListenersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of listener_collection.
	ListenerCollections   []GetNetworkLoadBalancerListenersListenerCollection `pulumi:"listenerCollections"`
	NetworkLoadBalancerId string                                              `pulumi:"networkLoadBalancerId"`
}
