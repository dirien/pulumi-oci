// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Instance Configurations in Oracle Cloud Infrastructure Core service.
//
// Lists the instance configurations in the specified compartment.
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
// 		_, err := oci.GetCoreInstanceConfigurations(ctx, &GetCoreInstanceConfigurationsArgs{
// 			CompartmentId: _var.Compartment_id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCoreInstanceConfigurations(ctx *pulumi.Context, args *GetCoreInstanceConfigurationsArgs, opts ...pulumi.InvokeOption) (*GetCoreInstanceConfigurationsResult, error) {
	var rv GetCoreInstanceConfigurationsResult
	err := ctx.Invoke("oci:index/getCoreInstanceConfigurations:GetCoreInstanceConfigurations", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreInstanceConfigurations.
type GetCoreInstanceConfigurationsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                                `pulumi:"compartmentId"`
	Filters       []GetCoreInstanceConfigurationsFilter `pulumi:"filters"`
}

// A collection of values returned by GetCoreInstanceConfigurations.
type GetCoreInstanceConfigurationsResult struct {
	// The OCID of the compartment.
	CompartmentId string                                `pulumi:"compartmentId"`
	Filters       []GetCoreInstanceConfigurationsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of instance_configurations.
	InstanceConfigurations []GetCoreInstanceConfigurationsInstanceConfiguration `pulumi:"instanceConfigurations"`
}
