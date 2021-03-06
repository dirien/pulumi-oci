// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Byoip Allocated Ranges in Oracle Cloud Infrastructure Core service.
//
// Lists the subranges of a BYOIP CIDR block currently allocated to an IP pool.
// Each `ByoipAllocatedRange` object also lists the IP pool where it is allocated.
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
// 		_, err := oci.GetCoreByoipAllocatedRanges(ctx, &GetCoreByoipAllocatedRangesArgs{
// 			ByoipRangeId: oci_core_byoip_range.Test_byoip_range.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCoreByoipAllocatedRanges(ctx *pulumi.Context, args *GetCoreByoipAllocatedRangesArgs, opts ...pulumi.InvokeOption) (*GetCoreByoipAllocatedRangesResult, error) {
	var rv GetCoreByoipAllocatedRangesResult
	err := ctx.Invoke("oci:index/getCoreByoipAllocatedRanges:GetCoreByoipAllocatedRanges", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreByoipAllocatedRanges.
type GetCoreByoipAllocatedRangesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `ByoipRange` resource containing the BYOIP CIDR block.
	ByoipRangeId string                              `pulumi:"byoipRangeId"`
	Filters      []GetCoreByoipAllocatedRangesFilter `pulumi:"filters"`
}

// A collection of values returned by GetCoreByoipAllocatedRanges.
type GetCoreByoipAllocatedRangesResult struct {
	// The list of byoip_allocated_range_collection.
	ByoipAllocatedRangeCollections []GetCoreByoipAllocatedRangesByoipAllocatedRangeCollection `pulumi:"byoipAllocatedRangeCollections"`
	ByoipRangeId                   string                                                     `pulumi:"byoipRangeId"`
	Filters                        []GetCoreByoipAllocatedRangesFilter                        `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}
