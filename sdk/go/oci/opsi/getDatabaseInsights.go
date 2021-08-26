// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package opsi

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Database Insights in Oracle Cloud Infrastructure Opsi service.
//
// Gets a list of database insights based on the query parameters specified. Either compartmentId or id query parameter must be specified.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/opsi"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Compartment_id
// 		opt1 := oci_opsi_enterprise_manager_bridge.Test_enterprise_manager_bridge.Id
// 		opt2 := _var.Database_insight_id
// 		_, err := opsi.GetDatabaseInsights(ctx, &opsi.GetDatabaseInsightsArgs{
// 			CompartmentId:             &opt0,
// 			DatabaseIds:               oci_database_database.Test_database.Id,
// 			DatabaseTypes:             _var.Database_insight_database_type,
// 			EnterpriseManagerBridgeId: &opt1,
// 			Fields:                    _var.Database_insight_fields,
// 			Id:                        &opt2,
// 			States:                    _var.Database_insight_state,
// 			Statuses:                  _var.Database_insight_status,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDatabaseInsights(ctx *pulumi.Context, args *GetDatabaseInsightsArgs, opts ...pulumi.InvokeOption) (*GetDatabaseInsightsResult, error) {
	var rv GetDatabaseInsightsResult
	err := ctx.Invoke("oci:opsi/getDatabaseInsights:getDatabaseInsights", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDatabaseInsights.
type GetDatabaseInsightsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// Optional list of database [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated DBaaS entity.
	DatabaseIds []string `pulumi:"databaseIds"`
	// Filter by one or more database type. Possible values are ADW-S, ATP-S, ADW-D, ATP-D, EXTERNAL-PDB, EXTERNAL-NONCDB.
	DatabaseTypes []string `pulumi:"databaseTypes"`
	// Unique Enterprise Manager bridge identifier
	EnterpriseManagerBridgeId *string `pulumi:"enterpriseManagerBridgeId"`
	// Specifies the fields to return in a database summary response. By default all fields are returned if omitted.
	Fields  []string                    `pulumi:"fields"`
	Filters []GetDatabaseInsightsFilter `pulumi:"filters"`
	// Optional database insight resource [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database insight resource.
	Id *string `pulumi:"id"`
	// Lifecycle states
	States []string `pulumi:"states"`
	// Resource Status
	Statuses []string `pulumi:"statuses"`
}

// A collection of values returned by getDatabaseInsights.
type GetDatabaseInsightsResult struct {
	// Compartment identifier of the database
	CompartmentId *string  `pulumi:"compartmentId"`
	DatabaseIds   []string `pulumi:"databaseIds"`
	// The list of database_insights_collection.
	DatabaseInsightsCollections []GetDatabaseInsightsDatabaseInsightsCollection `pulumi:"databaseInsightsCollections"`
	// Operations Insights internal representation of the database type.
	DatabaseTypes []string `pulumi:"databaseTypes"`
	// OPSI Enterprise Manager Bridge OCID
	EnterpriseManagerBridgeId *string                     `pulumi:"enterpriseManagerBridgeId"`
	Fields                    []string                    `pulumi:"fields"`
	Filters                   []GetDatabaseInsightsFilter `pulumi:"filters"`
	// Database insight identifier
	Id *string `pulumi:"id"`
	// The current state of the database.
	States []string `pulumi:"states"`
	// Indicates the status of a database insight in Operations Insights
	Statuses []string `pulumi:"statuses"`
}
