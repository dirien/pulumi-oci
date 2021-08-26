// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Autonomous Databases in Oracle Cloud Infrastructure Database service.
//
// Gets a list of Autonomous Databases based on the query parameters specified.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/database"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := oci_database_autonomous_container_database.Test_autonomous_container_database.Id
// 		opt1 := _var.Autonomous_database_db_version
// 		opt2 := _var.Autonomous_database_db_workload
// 		opt3 := _var.Autonomous_database_display_name
// 		opt4 := _var.Autonomous_database_infrastructure_type
// 		opt5 := _var.Autonomous_database_is_data_guard_enabled
// 		opt6 := _var.Autonomous_database_is_free_tier
// 		opt7 := _var.Autonomous_database_is_refreshable_clone
// 		opt8 := _var.Autonomous_database_state
// 		_, err := database.GetAutonomousDatabases(ctx, &database.GetAutonomousDatabasesArgs{
// 			CompartmentId:                 _var.Compartment_id,
// 			AutonomousContainerDatabaseId: &opt0,
// 			DbVersion:                     &opt1,
// 			DbWorkload:                    &opt2,
// 			DisplayName:                   &opt3,
// 			InfrastructureType:            &opt4,
// 			IsDataGuardEnabled:            &opt5,
// 			IsFreeTier:                    &opt6,
// 			IsRefreshableClone:            &opt7,
// 			State:                         &opt8,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetAutonomousDatabases(ctx *pulumi.Context, args *GetAutonomousDatabasesArgs, opts ...pulumi.InvokeOption) (*GetAutonomousDatabasesResult, error) {
	var rv GetAutonomousDatabasesResult
	err := ctx.Invoke("oci:database/getAutonomousDatabases:getAutonomousDatabases", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutonomousDatabases.
type GetAutonomousDatabasesArgs struct {
	// The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousContainerDatabaseId *string `pulumi:"autonomousContainerDatabaseId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only autonomous database resources that match the specified dbVersion.
	DbVersion *string `pulumi:"dbVersion"`
	// A filter to return only autonomous database resources that match the specified workload type.
	DbWorkload *string `pulumi:"dbWorkload"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string                        `pulumi:"displayName"`
	Filters     []GetAutonomousDatabasesFilter `pulumi:"filters"`
	// A filter to return only resources that match the given Infrastructure Type.
	InfrastructureType *string `pulumi:"infrastructureType"`
	// A filter to return only resources that have Data Guard enabled.
	IsDataGuardEnabled *bool `pulumi:"isDataGuardEnabled"`
	// Filter on the value of the resource's 'isFreeTier' property. A value of `true` returns only Always Free resources. A value of `false` excludes Always Free resources from the returned results. Omitting this parameter returns both Always Free and paid resources.
	IsFreeTier *bool `pulumi:"isFreeTier"`
	// Filter on the value of the resource's 'isRefreshableClone' property. A value of `true` returns only refreshable clones. A value of `false` excludes refreshable clones from the returned results. Omitting this parameter returns both refreshable clones and databases that are not refreshable clones.
	IsRefreshableClone *bool `pulumi:"isRefreshableClone"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
}

// A collection of values returned by getAutonomousDatabases.
type GetAutonomousDatabasesResult struct {
	// The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousContainerDatabaseId *string `pulumi:"autonomousContainerDatabaseId"`
	// The list of autonomous_databases.
	AutonomousDatabases []GetAutonomousDatabasesAutonomousDatabase `pulumi:"autonomousDatabases"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A valid Oracle Database version for Autonomous Database.
	DbVersion *string `pulumi:"dbVersion"`
	// The Autonomous Database workload type. The following values are valid:
	// * OLTP - indicates an Autonomous Transaction Processing database
	// * DW - indicates an Autonomous Data Warehouse database
	// * AJD - indicates an Autonomous JSON Database
	// * APEX - indicates an Autonomous Database with the Oracle APEX Application Development workload type.
	DbWorkload *string `pulumi:"dbWorkload"`
	// The user-friendly name for the Autonomous Database. The name does not have to be unique.
	DisplayName *string                        `pulumi:"displayName"`
	Filters     []GetAutonomousDatabasesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The infrastructure type this resource belongs to.
	InfrastructureType *string `pulumi:"infrastructureType"`
	// Indicates whether the Autonomous Database has Data Guard enabled.
	IsDataGuardEnabled *bool `pulumi:"isDataGuardEnabled"`
	// Indicates if this is an Always Free resource. The default value is false. Note that Always Free Autonomous Databases have 1 CPU and 20GB of memory. For Always Free databases, memory and CPU cannot be scaled.
	IsFreeTier *bool `pulumi:"isFreeTier"`
	// Indicates whether the Autonomous Database is a refreshable clone.
	IsRefreshableClone *bool `pulumi:"isRefreshableClone"`
	// The current state of the Autonomous Database.
	State *string `pulumi:"state"`
}
