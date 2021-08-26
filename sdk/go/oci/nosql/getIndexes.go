// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nosql

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Indexes in Oracle Cloud Infrastructure NoSQL Database service.
//
// Get a list of indexes on a table.
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
// 		opt0 := _var.Compartment_id
// 		opt1 := _var.Index_name
// 		opt2 := _var.Index_state
// 		_, err := nosql.GetIndexes(ctx, &nosql.GetIndexesArgs{
// 			TableNameOrId: oci_nosql_table_name_or.Test_table_name_or.Id,
// 			CompartmentId: &opt0,
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
func GetIndexes(ctx *pulumi.Context, args *GetIndexesArgs, opts ...pulumi.InvokeOption) (*GetIndexesResult, error) {
	var rv GetIndexesResult
	err := ctx.Invoke("oci:nosql/getIndexes:getIndexes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getIndexes.
type GetIndexesArgs struct {
	// The ID of a table's compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
	CompartmentId *string            `pulumi:"compartmentId"`
	Filters       []GetIndexesFilter `pulumi:"filters"`
	// A shell-globbing-style (*?[]) filter for names.
	Name *string `pulumi:"name"`
	// Filter list by the lifecycle state of the item.
	State *string `pulumi:"state"`
	// A table name within the compartment, or a table OCID.
	TableNameOrId string `pulumi:"tableNameOrId"`
}

// A collection of values returned by getIndexes.
type GetIndexesResult struct {
	// Compartment Identifier.
	CompartmentId *string            `pulumi:"compartmentId"`
	Filters       []GetIndexesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of index_collection.
	IndexCollections []GetIndexesIndexCollection `pulumi:"indexCollections"`
	// Index name.
	Name *string `pulumi:"name"`
	// The state of an index.
	State         *string `pulumi:"state"`
	TableNameOrId string  `pulumi:"tableNameOrId"`
}
