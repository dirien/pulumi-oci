// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Compute Image Capability Schema resource in Oracle Cloud Infrastructure Core service.
//
// Gets the specified Compute Image Capability Schema
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
// 		opt0 := _var.Compute_image_capability_schema_is_merge_enabled
// 		_, err := oci.GetCoreComputeImageCapabilitySchema(ctx, &GetCoreComputeImageCapabilitySchemaArgs{
// 			ComputeImageCapabilitySchemaId: oci_core_compute_image_capability_schema.Test_compute_image_capability_schema.Id,
// 			IsMergeEnabled:                 &opt0,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupCoreComputeImageCapabilitySchema(ctx *pulumi.Context, args *LookupCoreComputeImageCapabilitySchemaArgs, opts ...pulumi.InvokeOption) (*LookupCoreComputeImageCapabilitySchemaResult, error) {
	var rv LookupCoreComputeImageCapabilitySchemaResult
	err := ctx.Invoke("oci:index/getCoreComputeImageCapabilitySchema:GetCoreComputeImageCapabilitySchema", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreComputeImageCapabilitySchema.
type LookupCoreComputeImageCapabilitySchemaArgs struct {
	// The id of the compute image capability schema or the image ocid
	ComputeImageCapabilitySchemaId string `pulumi:"computeImageCapabilitySchemaId"`
	// Merge the image capability schema with the global image capability schema
	IsMergeEnabled *string `pulumi:"isMergeEnabled"`
}

// A collection of values returned by GetCoreComputeImageCapabilitySchema.
type LookupCoreComputeImageCapabilitySchemaResult struct {
	// The OCID of the compartment containing the compute global image capability schema
	CompartmentId string `pulumi:"compartmentId"`
	// The ocid of the compute global image capability schema
	ComputeGlobalImageCapabilitySchemaId string `pulumi:"computeGlobalImageCapabilitySchemaId"`
	// The name of the compute global image capability schema version
	ComputeGlobalImageCapabilitySchemaVersionName string `pulumi:"computeGlobalImageCapabilitySchemaVersionName"`
	ComputeImageCapabilitySchemaId                string `pulumi:"computeImageCapabilitySchemaId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A user-friendly name for the compute global image capability schema
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The compute image capability schema [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	Id string `pulumi:"id"`
	// The OCID of the image associated with this compute image capability schema
	ImageId        string  `pulumi:"imageId"`
	IsMergeEnabled *string `pulumi:"isMergeEnabled"`
	// The map of each capability name to its ImageCapabilityDescriptor.
	SchemaData map[string]interface{} `pulumi:"schemaData"`
	// The date and time the compute image capability schema was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
}