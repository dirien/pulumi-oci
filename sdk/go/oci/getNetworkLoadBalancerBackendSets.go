// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Backend Sets in Oracle Cloud Infrastructure Network Load Balancer service.
//
// Lists all backend sets associated with a given network load balancer.
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
// 		_, err := oci.GetNetworkLoadBalancerBackendSets(ctx, &GetNetworkLoadBalancerBackendSetsArgs{
// 			NetworkLoadBalancerId: oci_network_load_balancer_network_load_balancer.Test_network_load_balancer.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetNetworkLoadBalancerBackendSets(ctx *pulumi.Context, args *GetNetworkLoadBalancerBackendSetsArgs, opts ...pulumi.InvokeOption) (*GetNetworkLoadBalancerBackendSetsResult, error) {
	var rv GetNetworkLoadBalancerBackendSetsResult
	err := ctx.Invoke("oci:index/getNetworkLoadBalancerBackendSets:GetNetworkLoadBalancerBackendSets", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetNetworkLoadBalancerBackendSets.
type GetNetworkLoadBalancerBackendSetsArgs struct {
	Filters []GetNetworkLoadBalancerBackendSetsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
	NetworkLoadBalancerId string `pulumi:"networkLoadBalancerId"`
}

// A collection of values returned by GetNetworkLoadBalancerBackendSets.
type GetNetworkLoadBalancerBackendSetsResult struct {
	// The list of backend_set_collection.
	BackendSetCollections []GetNetworkLoadBalancerBackendSetsBackendSetCollection `pulumi:"backendSetCollections"`
	Filters               []GetNetworkLoadBalancerBackendSetsFilter               `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                    string `pulumi:"id"`
	NetworkLoadBalancerId string `pulumi:"networkLoadBalancerId"`
}
