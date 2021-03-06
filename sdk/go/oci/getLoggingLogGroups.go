// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Log Groups in Oracle Cloud Infrastructure Logging service.
//
// Lists all log groups for the specified compartment or tenancy.
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
// 		opt0 := _var.Log_group_display_name
// 		opt1 := _var.Log_group_is_compartment_id_in_subtree
// 		_, err := oci.GetLoggingLogGroups(ctx, &GetLoggingLogGroupsArgs{
// 			CompartmentId:            _var.Compartment_id,
// 			DisplayName:              &opt0,
// 			IsCompartmentIdInSubtree: &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetLoggingLogGroups(ctx *pulumi.Context, args *GetLoggingLogGroupsArgs, opts ...pulumi.InvokeOption) (*GetLoggingLogGroupsResult, error) {
	var rv GetLoggingLogGroupsResult
	err := ctx.Invoke("oci:index/getLoggingLogGroups:GetLoggingLogGroups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetLoggingLogGroups.
type GetLoggingLogGroupsArgs struct {
	// Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
	CompartmentId string `pulumi:"compartmentId"`
	// Resource name
	DisplayName *string                     `pulumi:"displayName"`
	Filters     []GetLoggingLogGroupsFilter `pulumi:"filters"`
	// Specifies whether or not nested compartments should be traversed. Defaults to false.
	IsCompartmentIdInSubtree *bool `pulumi:"isCompartmentIdInSubtree"`
}

// A collection of values returned by GetLoggingLogGroups.
type GetLoggingLogGroupsResult struct {
	// The OCID of the compartment that the resource belongs to.
	CompartmentId string `pulumi:"compartmentId"`
	// The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
	DisplayName *string                     `pulumi:"displayName"`
	Filters     []GetLoggingLogGroupsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                       string `pulumi:"id"`
	IsCompartmentIdInSubtree *bool  `pulumi:"isCompartmentIdInSubtree"`
	// The list of log_groups.
	LogGroups []GetLoggingLogGroupsLogGroup `pulumi:"logGroups"`
}
