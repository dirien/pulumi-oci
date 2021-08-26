// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package bds

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Bds Instances in Oracle Cloud Infrastructure Big Data Service service.
//
// Returns a list of all Big Data Service clusters in a compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/bds"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Bds_instance_display_name
// 		opt1 := _var.Bds_instance_state
// 		_, err := bds.GetBdsInstances(ctx, &bds.GetBdsInstancesArgs{
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
func GetBdsInstances(ctx *pulumi.Context, args *GetBdsInstancesArgs, opts ...pulumi.InvokeOption) (*GetBdsInstancesResult, error) {
	var rv GetBdsInstancesResult
	err := ctx.Invoke("oci:bds/getBdsInstances:getBdsInstances", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getBdsInstances.
type GetBdsInstancesArgs struct {
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                 `pulumi:"displayName"`
	Filters     []GetBdsInstancesFilter `pulumi:"filters"`
	// The state of the cluster.
	State *string `pulumi:"state"`
}

// A collection of values returned by getBdsInstances.
type GetBdsInstancesResult struct {
	// The list of bds_instances.
	BdsInstances []GetBdsInstancesBdsInstance `pulumi:"bdsInstances"`
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The name of the node.
	DisplayName *string                 `pulumi:"displayName"`
	Filters     []GetBdsInstancesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The state of the cluster.
	State *string `pulumi:"state"`
}