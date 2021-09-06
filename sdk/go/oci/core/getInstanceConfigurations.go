// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package core

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
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/core"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := core.GetInstanceConfigurations(ctx, &core.GetInstanceConfigurationsArgs{
// 			CompartmentId: _var.Compartment_id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetInstanceConfigurations(ctx *pulumi.Context, args *GetInstanceConfigurationsArgs, opts ...pulumi.InvokeOption) (*GetInstanceConfigurationsResult, error) {
	var rv GetInstanceConfigurationsResult
	err := ctx.Invoke("oci:core/getInstanceConfigurations:getInstanceConfigurations", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getInstanceConfigurations.
type GetInstanceConfigurationsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                            `pulumi:"compartmentId"`
	Filters       []GetInstanceConfigurationsFilter `pulumi:"filters"`
}

// A collection of values returned by getInstanceConfigurations.
type GetInstanceConfigurationsResult struct {
	// The OCID of the compartment.
	CompartmentId string                            `pulumi:"compartmentId"`
	Filters       []GetInstanceConfigurationsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of instance_configurations.
	InstanceConfigurations []GetInstanceConfigurationsInstanceConfiguration `pulumi:"instanceConfigurations"`
}
