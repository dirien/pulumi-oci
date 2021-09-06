// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nosql

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Index resource in Oracle Cloud Infrastructure NoSQL Database service.
//
// Get information about a single index.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/nosql"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := nosql.LookupIndex(ctx, &nosql.LookupIndexArgs{
// 			IndexName:     oci_nosql_index.Test_index.Name,
// 			TableNameOrId: oci_nosql_table_name_or.Test_table_name_or.Id,
// 			CompartmentId: _var.Compartment_id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupIndex(ctx *pulumi.Context, args *LookupIndexArgs, opts ...pulumi.InvokeOption) (*LookupIndexResult, error) {
	var rv LookupIndexResult
	err := ctx.Invoke("oci:nosql/getIndex:getIndex", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getIndex.
type LookupIndexArgs struct {
	// The ID of a table's compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
	CompartmentId string `pulumi:"compartmentId"`
	// The name of a table's index.
	IndexName string `pulumi:"indexName"`
	// A table name within the compartment, or a table OCID.
	TableNameOrId string `pulumi:"tableNameOrId"`
}

// A collection of values returned by getIndex.
type LookupIndexResult struct {
	// Compartment Identifier.
	CompartmentId string `pulumi:"compartmentId"`
	Id            string `pulumi:"id"`
	IndexName     string `pulumi:"indexName"`
	IsIfNotExists bool   `pulumi:"isIfNotExists"`
	// A set of keys for a secondary index.
	Keys []GetIndexKey `pulumi:"keys"`
	// A message describing the current state in more detail.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Index name.
	Name string `pulumi:"name"`
	// The state of an index.
	State string `pulumi:"state"`
	// the OCID of the table to which this index belongs.
	TableId string `pulumi:"tableId"`
	// The name of the table to which this index belongs.
	TableName     string `pulumi:"tableName"`
	TableNameOrId string `pulumi:"tableNameOrId"`
}
