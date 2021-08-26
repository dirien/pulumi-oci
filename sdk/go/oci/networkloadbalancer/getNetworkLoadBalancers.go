// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package networkloadbalancer

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Network Load Balancers in Oracle Cloud Infrastructure Network Load Balancer service.
//
// Returns a list of network load balancers.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/networkloadbalancer"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Network_load_balancer_display_name
// 		opt1 := _var.Network_load_balancer_state
// 		_, err := networkloadbalancer.GetNetworkLoadBalancers(ctx, &networkloadbalancer.GetNetworkLoadBalancersArgs{
// 			CompartmentId: _var.Compartment_id,
// 			DisplayName:   &opt0,
// 			State:         &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetNetworkLoadBalancers(ctx *pulumi.Context, args *GetNetworkLoadBalancersArgs, opts ...pulumi.InvokeOption) (*GetNetworkLoadBalancersResult, error) {
	var rv GetNetworkLoadBalancersResult
	err := ctx.Invoke("oci:networkloadbalancer/getNetworkLoadBalancers:getNetworkLoadBalancers", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNetworkLoadBalancers.
type GetNetworkLoadBalancersArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancers to list.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                         `pulumi:"displayName"`
	Filters     []GetNetworkLoadBalancersFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state.
	State *string `pulumi:"state"`
}

// A collection of values returned by getNetworkLoadBalancers.
type GetNetworkLoadBalancersResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancer.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name, which does not have to be unique, and can be changed.  Example: `exampleLoadBalancer`
	DisplayName *string                         `pulumi:"displayName"`
	Filters     []GetNetworkLoadBalancersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of network_load_balancer_collection.
	NetworkLoadBalancerCollections []GetNetworkLoadBalancersNetworkLoadBalancerCollection `pulumi:"networkLoadBalancerCollections"`
	// The current state of the network load balancer.
	State *string `pulumi:"state"`
}