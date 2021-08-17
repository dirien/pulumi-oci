// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Node Pools in Oracle Cloud Infrastructure Container Engine service.
//
// List all the node pools in a compartment, and optionally filter by cluster.
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
// 		opt0 := oci_containerengine_cluster.Test_cluster.Id
// 		opt1 := _var.Node_pool_name
// 		_, err := oci.GetContainerengineNodePools(ctx, &GetContainerengineNodePoolsArgs{
// 			CompartmentId: _var.Compartment_id,
// 			ClusterId:     &opt0,
// 			Name:          &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetContainerengineNodePools(ctx *pulumi.Context, args *GetContainerengineNodePoolsArgs, opts ...pulumi.InvokeOption) (*GetContainerengineNodePoolsResult, error) {
	var rv GetContainerengineNodePoolsResult
	err := ctx.Invoke("oci:index/getContainerengineNodePools:GetContainerengineNodePools", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetContainerengineNodePools.
type GetContainerengineNodePoolsArgs struct {
	// The OCID of the cluster.
	ClusterId *string `pulumi:"clusterId"`
	// The OCID of the compartment.
	CompartmentId string                              `pulumi:"compartmentId"`
	Filters       []GetContainerengineNodePoolsFilter `pulumi:"filters"`
	// The name to filter on.
	Name *string `pulumi:"name"`
}

// A collection of values returned by GetContainerengineNodePools.
type GetContainerengineNodePoolsResult struct {
	// The OCID of the cluster to which this node pool is attached.
	ClusterId *string `pulumi:"clusterId"`
	// The OCID of the compartment in which the node pool exists.
	CompartmentId string                              `pulumi:"compartmentId"`
	Filters       []GetContainerengineNodePoolsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The name of the node.
	Name *string `pulumi:"name"`
	// The list of node_pools.
	NodePools []GetContainerengineNodePoolsNodePool `pulumi:"nodePools"`
}