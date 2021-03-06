// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Db Node Console Connections in Oracle Cloud Infrastructure Database service.
//
// Lists the console connections for the specified database node.
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
// 		_, err := oci.GetDatabaseDbNodeConsoleConnections(ctx, &GetDatabaseDbNodeConsoleConnectionsArgs{
// 			DbNodeId: oci_database_db_node.Test_db_node.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDatabaseDbNodeConsoleConnections(ctx *pulumi.Context, args *GetDatabaseDbNodeConsoleConnectionsArgs, opts ...pulumi.InvokeOption) (*GetDatabaseDbNodeConsoleConnectionsResult, error) {
	var rv GetDatabaseDbNodeConsoleConnectionsResult
	err := ctx.Invoke("oci:index/getDatabaseDbNodeConsoleConnections:GetDatabaseDbNodeConsoleConnections", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetDatabaseDbNodeConsoleConnections.
type GetDatabaseDbNodeConsoleConnectionsArgs struct {
	// The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbNodeId string                                      `pulumi:"dbNodeId"`
	Filters  []GetDatabaseDbNodeConsoleConnectionsFilter `pulumi:"filters"`
}

// A collection of values returned by GetDatabaseDbNodeConsoleConnections.
type GetDatabaseDbNodeConsoleConnectionsResult struct {
	// The list of console_connections.
	ConsoleConnections []GetDatabaseDbNodeConsoleConnectionsConsoleConnection `pulumi:"consoleConnections"`
	// The OCID of the database node.
	DbNodeId string                                      `pulumi:"dbNodeId"`
	Filters  []GetDatabaseDbNodeConsoleConnectionsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}
