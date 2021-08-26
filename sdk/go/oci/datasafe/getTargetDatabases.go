// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Target Databases in Oracle Cloud Infrastructure Data Safe service.
//
// Returns the list of registered target databases in Data Safe.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/datasafe"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Target_database_access_level
// 		opt1 := _var.Target_database_compartment_id_in_subtree
// 		opt2 := _var.Target_database_database_type
// 		opt3 := _var.Target_database_display_name
// 		opt4 := _var.Target_database_infrastructure_type
// 		opt5 := _var.Target_database_state
// 		opt6 := oci_data_safe_target_database.Test_target_database.Id
// 		_, err := datasafe.GetTargetDatabases(ctx, &datasafe.GetTargetDatabasesArgs{
// 			CompartmentId:          _var.Compartment_id,
// 			AccessLevel:            &opt0,
// 			CompartmentIdInSubtree: &opt1,
// 			DatabaseType:           &opt2,
// 			DisplayName:            &opt3,
// 			InfrastructureType:     &opt4,
// 			State:                  &opt5,
// 			TargetDatabaseId:       &opt6,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetTargetDatabases(ctx *pulumi.Context, args *GetTargetDatabasesArgs, opts ...pulumi.InvokeOption) (*GetTargetDatabasesResult, error) {
	var rv GetTargetDatabasesResult
	err := ctx.Invoke("oci:datasafe/getTargetDatabases:getTargetDatabases", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getTargetDatabases.
type GetTargetDatabasesArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel *string `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree *bool `pulumi:"compartmentIdInSubtree"`
	// A filter to return target databases that match the database type of the target database.
	DatabaseType *string `pulumi:"databaseType"`
	// A filter to return only resources that match the specified display name.
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetTargetDatabasesFilter `pulumi:"filters"`
	// A filter to return target databases that match the infrastructure type of the target database.
	InfrastructureType *string `pulumi:"infrastructureType"`
	// A filter to return the target databases that matches the current state of the target database.
	State *string `pulumi:"state"`
	// A filter to return the target database that matches the specified OCID.
	TargetDatabaseId *string `pulumi:"targetDatabaseId"`
}

// A collection of values returned by getTargetDatabases.
type GetTargetDatabasesResult struct {
	AccessLevel *string `pulumi:"accessLevel"`
	// The OCID of the compartment which contains the Data Safe target database.
	CompartmentId          string `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool  `pulumi:"compartmentIdInSubtree"`
	// The database type.
	DatabaseType *string `pulumi:"databaseType"`
	// The display name of the target database in Data Safe.
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetTargetDatabasesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The infrastructure type the database is running on.
	InfrastructureType *string `pulumi:"infrastructureType"`
	// The current state of the target database in Data Safe.
	State            *string `pulumi:"state"`
	TargetDatabaseId *string `pulumi:"targetDatabaseId"`
	// The list of target_databases.
	TargetDatabases []GetTargetDatabasesTargetDatabase `pulumi:"targetDatabases"`
}
