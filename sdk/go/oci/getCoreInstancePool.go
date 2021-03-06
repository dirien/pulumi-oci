// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Instance Pool resource in Oracle Cloud Infrastructure Core service.
//
// Gets the specified instance pool
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
// 		_, err := oci.GetCoreInstancePool(ctx, &GetCoreInstancePoolArgs{
// 			InstancePoolId: oci_core_instance_pool.Test_instance_pool.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupCoreInstancePool(ctx *pulumi.Context, args *LookupCoreInstancePoolArgs, opts ...pulumi.InvokeOption) (*LookupCoreInstancePoolResult, error) {
	var rv LookupCoreInstancePoolResult
	err := ctx.Invoke("oci:index/getCoreInstancePool:GetCoreInstancePool", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreInstancePool.
type LookupCoreInstancePoolArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
	InstancePoolId string `pulumi:"instancePoolId"`
}

// A collection of values returned by GetCoreInstancePool.
type LookupCoreInstancePoolResult struct {
	ActualSize int `pulumi:"actualSize"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attachment.
	Id string `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration associated with the instance pool.
	InstanceConfigurationId string `pulumi:"instanceConfigurationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool of the load balancer attachment.
	InstancePoolId string `pulumi:"instancePoolId"`
	// The load balancers attached to the instance pool.
	LoadBalancers []GetCoreInstancePoolLoadBalancer `pulumi:"loadBalancers"`
	// The placement configurations for the instance pool.
	PlacementConfigurations []GetCoreInstancePoolPlacementConfiguration `pulumi:"placementConfigurations"`
	// The number of actual instances in the instance pool on the cloud. This attribute will be different when instance pool is used along with autoScaling Configuration.
	Size int `pulumi:"size"`
	// The current state of the instance pool.
	State string `pulumi:"state"`
	// The date and time the instance pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
}
