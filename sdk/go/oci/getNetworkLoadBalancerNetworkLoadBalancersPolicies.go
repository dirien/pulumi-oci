// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Network Load Balancers Policies in Oracle Cloud Infrastructure Network Load Balancer service.
//
// Lists the available network load balancer policies.
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
// 		_, err := oci.GetNetworkLoadBalancerNetworkLoadBalancersPolicies(ctx, nil, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetNetworkLoadBalancerNetworkLoadBalancersPolicies(ctx *pulumi.Context, args *GetNetworkLoadBalancerNetworkLoadBalancersPoliciesArgs, opts ...pulumi.InvokeOption) (*GetNetworkLoadBalancerNetworkLoadBalancersPoliciesResult, error) {
	var rv GetNetworkLoadBalancerNetworkLoadBalancersPoliciesResult
	err := ctx.Invoke("oci:index/getNetworkLoadBalancerNetworkLoadBalancersPolicies:GetNetworkLoadBalancerNetworkLoadBalancersPolicies", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetNetworkLoadBalancerNetworkLoadBalancersPolicies.
type GetNetworkLoadBalancerNetworkLoadBalancersPoliciesArgs struct {
	Filters []GetNetworkLoadBalancerNetworkLoadBalancersPoliciesFilter `pulumi:"filters"`
}

// A collection of values returned by GetNetworkLoadBalancerNetworkLoadBalancersPolicies.
type GetNetworkLoadBalancerNetworkLoadBalancersPoliciesResult struct {
	Filters []GetNetworkLoadBalancerNetworkLoadBalancersPoliciesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of network_load_balancers_policy_collection.
	NetworkLoadBalancersPolicyCollections []GetNetworkLoadBalancerNetworkLoadBalancersPoliciesNetworkLoadBalancersPolicyCollection `pulumi:"networkLoadBalancersPolicyCollections"`
}
