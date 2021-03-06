// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func GetLoadBalancers(ctx *pulumi.Context, args *GetLoadBalancersArgs, opts ...pulumi.InvokeOption) (*GetLoadBalancersResult, error) {
	var rv GetLoadBalancersResult
	err := ctx.Invoke("oci:index/getLoadBalancers:GetLoadBalancers", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetLoadBalancers.
type GetLoadBalancersArgs struct {
	CompartmentId string                   `pulumi:"compartmentId"`
	Detail        *string                  `pulumi:"detail"`
	DisplayName   *string                  `pulumi:"displayName"`
	Filters       []GetLoadBalancersFilter `pulumi:"filters"`
	State         *string                  `pulumi:"state"`
}

// A collection of values returned by GetLoadBalancers.
type GetLoadBalancersResult struct {
	CompartmentId string                   `pulumi:"compartmentId"`
	Detail        *string                  `pulumi:"detail"`
	DisplayName   *string                  `pulumi:"displayName"`
	Filters       []GetLoadBalancersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id            string                         `pulumi:"id"`
	LoadBalancers []GetLoadBalancersLoadBalancer `pulumi:"loadBalancers"`
	State         *string                        `pulumi:"state"`
}
