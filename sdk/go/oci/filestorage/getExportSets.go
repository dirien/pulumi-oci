// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package filestorage

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Export Sets in Oracle Cloud Infrastructure File Storage service.
//
// Lists the export set resources in the specified compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/filestorage"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Export_set_display_name
// 		opt1 := _var.Export_set_id
// 		opt2 := _var.Export_set_state
// 		_, err := filestorage.GetExportSets(ctx, &filestorage.GetExportSetsArgs{
// 			AvailabilityDomain: _var.Export_set_availability_domain,
// 			CompartmentId:      _var.Compartment_id,
// 			DisplayName:        &opt0,
// 			Id:                 &opt1,
// 			State:              &opt2,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetExportSets(ctx *pulumi.Context, args *GetExportSetsArgs, opts ...pulumi.InvokeOption) (*GetExportSetsResult, error) {
	var rv GetExportSetsResult
	err := ctx.Invoke("oci:filestorage/getExportSets:getExportSets", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getExportSets.
type GetExportSetsArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
	DisplayName *string               `pulumi:"displayName"`
	Filters     []GetExportSetsFilter `pulumi:"filters"`
	// Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
	Id *string `pulumi:"id"`
	// Filter results by the specified lifecycle state. Must be a valid state for the resource type.
	State *string `pulumi:"state"`
}

// A collection of values returned by getExportSets.
type GetExportSetsResult struct {
	// The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
	DisplayName *string `pulumi:"displayName"`
	// The list of export_sets.
	ExportSets []GetExportSetsExportSet `pulumi:"exportSets"`
	Filters    []GetExportSetsFilter    `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export set.
	Id *string `pulumi:"id"`
	// The current state of the export set.
	State *string `pulumi:"state"`
}
