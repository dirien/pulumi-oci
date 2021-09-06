// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package loadbalancer

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Load Balancers in Oracle Cloud Infrastructure Load Balancer service.
//
// Lists all load balancers in the specified compartment.
//
// ## Supported Aliases
//
// * `ociLoadBalancers`
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/loadbalancer"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Load_balancer_detail
// 		opt1 := _var.Load_balancer_display_name
// 		opt2 := _var.Load_balancer_state
// 		_, err := loadbalancer.GetLoadBalancers(ctx, &loadbalancer.GetLoadBalancersArgs{
// 			CompartmentId: _var.Compartment_id,
// 			Detail:        &opt0,
// 			DisplayName:   &opt1,
// 			State:         &opt2,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetLoadBalancers(ctx *pulumi.Context, args *GetLoadBalancersArgs, opts ...pulumi.InvokeOption) (*GetLoadBalancersResult, error) {
	var rv GetLoadBalancersResult
	err := ctx.Invoke("oci:loadbalancer/getLoadBalancers:getLoadBalancers", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getLoadBalancers.
type GetLoadBalancersArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the load balancers to list.
	CompartmentId string `pulumi:"compartmentId"`
	// The level of detail to return for each result. Can be `full` or `simple`.  Example: `full`
	Detail *string `pulumi:"detail"`
	// A filter to return only resources that match the given display name exactly.  Example: `exampleLoadBalancer`
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetLoadBalancersFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state.  Example: `SUCCEEDED`
	State *string `pulumi:"state"`
}

// A collection of values returned by getLoadBalancers.
type GetLoadBalancersResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the load balancer.
	CompartmentId string  `pulumi:"compartmentId"`
	Detail        *string `pulumi:"detail"`
	// A user-friendly name. It does not have to be unique, and it is changeable.  Example: `exampleLoadBalancer`
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetLoadBalancersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of load_balancers.
	LoadBalancers []GetLoadBalancersLoadBalancer `pulumi:"loadBalancers"`
	// The current state of the load balancer.
	State *string `pulumi:"state"`
}
