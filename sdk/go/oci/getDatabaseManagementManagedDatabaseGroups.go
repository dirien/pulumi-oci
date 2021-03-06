// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Managed Database Groups in Oracle Cloud Infrastructure Database Management service.
//
// Gets the Managed Database Group for a specific ID or the list of Managed Database Groups in
// a specific compartment. Managed Database Groups can also be filtered based on the name parameter.
// Only one of the parameters, ID or name should be provided. If none of these parameters is provided,
// all the Managed Database Groups in the compartment are listed.
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
// 		opt0 := _var.Managed_database_group_id
// 		opt1 := _var.Managed_database_group_name
// 		opt2 := _var.Managed_database_group_state
// 		_, err := oci.GetDatabaseManagementManagedDatabaseGroups(ctx, &GetDatabaseManagementManagedDatabaseGroupsArgs{
// 			CompartmentId: _var.Compartment_id,
// 			Id:            &opt0,
// 			Name:          &opt1,
// 			State:         &opt2,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDatabaseManagementManagedDatabaseGroups(ctx *pulumi.Context, args *GetDatabaseManagementManagedDatabaseGroupsArgs, opts ...pulumi.InvokeOption) (*GetDatabaseManagementManagedDatabaseGroupsResult, error) {
	var rv GetDatabaseManagementManagedDatabaseGroupsResult
	err := ctx.Invoke("oci:index/getDatabaseManagementManagedDatabaseGroups:GetDatabaseManagementManagedDatabaseGroups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetDatabaseManagementManagedDatabaseGroups.
type GetDatabaseManagementManagedDatabaseGroupsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                                             `pulumi:"compartmentId"`
	Filters       []GetDatabaseManagementManagedDatabaseGroupsFilter `pulumi:"filters"`
	// The identifier of the resource. Only one of the parameters, id or name should be provided.
	Id *string `pulumi:"id"`
	// A filter to return only resources that match the entire name. Only one of the parameters, id or name should be provided
	Name *string `pulumi:"name"`
	// The lifecycle state of a resource.
	State *string `pulumi:"state"`
}

// A collection of values returned by GetDatabaseManagementManagedDatabaseGroups.
type GetDatabaseManagementManagedDatabaseGroupsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database resides.
	CompartmentId string                                             `pulumi:"compartmentId"`
	Filters       []GetDatabaseManagementManagedDatabaseGroupsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	Id *string `pulumi:"id"`
	// The list of managed_database_group_collection.
	ManagedDatabaseGroupCollections []GetDatabaseManagementManagedDatabaseGroupsManagedDatabaseGroupCollection `pulumi:"managedDatabaseGroupCollections"`
	// The name of the Managed Database Group.
	Name *string `pulumi:"name"`
	// The current lifecycle state of the Managed Database Group.
	State *string `pulumi:"state"`
}
