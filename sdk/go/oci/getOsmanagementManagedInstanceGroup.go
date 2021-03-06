// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Managed Instance Group resource in Oracle Cloud Infrastructure OS Management service.
//
// Returns a specific Managed Instance Group.
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
// 		_, err := oci.GetOsmanagementManagedInstanceGroup(ctx, &GetOsmanagementManagedInstanceGroupArgs{
// 			ManagedInstanceGroupId: oci_osmanagement_managed_instance_group.Test_managed_instance_group.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupOsmanagementManagedInstanceGroup(ctx *pulumi.Context, args *LookupOsmanagementManagedInstanceGroupArgs, opts ...pulumi.InvokeOption) (*LookupOsmanagementManagedInstanceGroupResult, error) {
	var rv LookupOsmanagementManagedInstanceGroupResult
	err := ctx.Invoke("oci:index/getOsmanagementManagedInstanceGroup:GetOsmanagementManagedInstanceGroup", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetOsmanagementManagedInstanceGroup.
type LookupOsmanagementManagedInstanceGroupArgs struct {
	// OCID for the managed instance group
	ManagedInstanceGroupId string `pulumi:"managedInstanceGroupId"`
}

// A collection of values returned by GetOsmanagementManagedInstanceGroup.
type LookupOsmanagementManagedInstanceGroupResult struct {
	// OCID for the Compartment
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Information specified by the user about the managed instance group
	Description string `pulumi:"description"`
	// User friendly name
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// unique identifier that is immutable on creation
	Id                     string `pulumi:"id"`
	ManagedInstanceCount   int    `pulumi:"managedInstanceCount"`
	ManagedInstanceGroupId string `pulumi:"managedInstanceGroupId"`
	// list of Managed Instances in the group
	ManagedInstances []GetOsmanagementManagedInstanceGroupManagedInstance `pulumi:"managedInstances"`
	// The Operating System type of the managed instance.
	OsFamily string `pulumi:"osFamily"`
	// The current state of the Software Source.
	State string `pulumi:"state"`
}
