// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Db Node Console Connection resource in Oracle Cloud Infrastructure Database service.
//
// Gets the specified database node console connection's information.
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
// 		_, err := database.LookupDbNodeConsoleConnection(ctx, &database.LookupDbNodeConsoleConnectionArgs{
// 			DbNodeId: oci_database_db_node.Test_db_node.Id,
// 			Id:       _var.Db_node_console_connection_id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupDbNodeConsoleConnection(ctx *pulumi.Context, args *LookupDbNodeConsoleConnectionArgs, opts ...pulumi.InvokeOption) (*LookupDbNodeConsoleConnectionResult, error) {
	var rv LookupDbNodeConsoleConnectionResult
	err := ctx.Invoke("oci:database/getDbNodeConsoleConnection:getDbNodeConsoleConnection", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDbNodeConsoleConnection.
type LookupDbNodeConsoleConnectionArgs struct {
	// The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbNodeId string `pulumi:"dbNodeId"`
	// The OCID of the console connection.
	Id string `pulumi:"id"`
}

// A collection of values returned by getDbNodeConsoleConnection.
type LookupDbNodeConsoleConnectionResult struct {
	// The OCID of the compartment to contain the console connection.
	CompartmentId string `pulumi:"compartmentId"`
	// The SSH connection string for the console connection.
	ConnectionString string `pulumi:"connectionString"`
	// The OCID of the database node.
	DbNodeId string `pulumi:"dbNodeId"`
	// The SSH public key fingerprint for the console connection.
	Fingerprint string `pulumi:"fingerprint"`
	// The OCID of the console connection.
	Id        string `pulumi:"id"`
	PublicKey string `pulumi:"publicKey"`
	// The current state of the console connection.
	State string `pulumi:"state"`
}
