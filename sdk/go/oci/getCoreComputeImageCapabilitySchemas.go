// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Compute Image Capability Schemas in Oracle Cloud Infrastructure Core service.
//
// Lists Compute Image Capability Schema in the specified compartment. You can also query by a specific imageId.
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
// 		opt0 := _var.Compartment_id
// 		opt1 := _var.Compute_image_capability_schema_display_name
// 		opt2 := oci_core_image.Test_image.Id
// 		_, err := oci.GetCoreComputeImageCapabilitySchemas(ctx, &GetCoreComputeImageCapabilitySchemasArgs{
// 			CompartmentId: &opt0,
// 			DisplayName:   &opt1,
// 			ImageId:       &opt2,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCoreComputeImageCapabilitySchemas(ctx *pulumi.Context, args *GetCoreComputeImageCapabilitySchemasArgs, opts ...pulumi.InvokeOption) (*GetCoreComputeImageCapabilitySchemasResult, error) {
	var rv GetCoreComputeImageCapabilitySchemasResult
	err := ctx.Invoke("oci:index/getCoreComputeImageCapabilitySchemas:GetCoreComputeImageCapabilitySchemas", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreComputeImageCapabilitySchemas.
type GetCoreComputeImageCapabilitySchemasArgs struct {
	// A filter to return only resources that match the given compartment OCID exactly.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string                                      `pulumi:"displayName"`
	Filters     []GetCoreComputeImageCapabilitySchemasFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an image.
	ImageId *string `pulumi:"imageId"`
}

// A collection of values returned by GetCoreComputeImageCapabilitySchemas.
type GetCoreComputeImageCapabilitySchemasResult struct {
	// The OCID of the compartment containing the compute global image capability schema
	CompartmentId *string `pulumi:"compartmentId"`
	// The list of compute_image_capability_schemas.
	ComputeImageCapabilitySchemas []GetCoreComputeImageCapabilitySchemasComputeImageCapabilitySchema `pulumi:"computeImageCapabilitySchemas"`
	// A user-friendly name for the compute global image capability schema
	DisplayName *string                                      `pulumi:"displayName"`
	Filters     []GetCoreComputeImageCapabilitySchemasFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The OCID of the image associated with this compute image capability schema
	ImageId *string `pulumi:"imageId"`
}
