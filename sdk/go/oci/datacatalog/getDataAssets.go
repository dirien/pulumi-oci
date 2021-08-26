// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package datacatalog

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Data Assets in Oracle Cloud Infrastructure Data Catalog service.
//
// Returns a list of data assets within a data catalog.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/datacatalog"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := oci_datacatalog_created_by.Test_created_by.Id
// 		opt1 := _var.Data_asset_display_name
// 		opt2 := _var.Data_asset_display_name_contains
// 		opt3 := _var.Data_asset_external_key
// 		opt4 := _var.Data_asset_state
// 		opt5 := _var.Data_asset_type_key
// 		_, err := datacatalog.GetDataAssets(ctx, &datacatalog.GetDataAssetsArgs{
// 			CatalogId:           oci_datacatalog_catalog.Test_catalog.Id,
// 			CreatedById:         &opt0,
// 			DisplayName:         &opt1,
// 			DisplayNameContains: &opt2,
// 			ExternalKey:         &opt3,
// 			Fields:              _var.Data_asset_fields,
// 			State:               &opt4,
// 			TimeCreated:         _var.Data_asset_time_created,
// 			TimeUpdated:         _var.Data_asset_time_updated,
// 			TypeKey:             &opt5,
// 			UpdatedById:         oci_datacatalog_updated_by.Test_updated_by.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDataAssets(ctx *pulumi.Context, args *GetDataAssetsArgs, opts ...pulumi.InvokeOption) (*GetDataAssetsResult, error) {
	var rv GetDataAssetsResult
	err := ctx.Invoke("oci:datacatalog/getDataAssets:getDataAssets", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDataAssets.
type GetDataAssetsArgs struct {
	// Unique catalog identifier.
	CatalogId string `pulumi:"catalogId"`
	// OCID of the user who created the resource.
	CreatedById *string `pulumi:"createdById"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string `pulumi:"displayName"`
	// A filter to return only resources that match display name pattern given. The match is not case sensitive. For Example : /folders?displayNameContains=Cu.* The above would match all folders with display name that starts with "Cu".
	DisplayNameContains *string `pulumi:"displayNameContains"`
	// Unique external identifier of this resource in the external source system.
	ExternalKey *string `pulumi:"externalKey"`
	// Specifies the fields to return in a data asset summary response.
	Fields  []string              `pulumi:"fields"`
	Filters []GetDataAssetsFilter `pulumi:"filters"`
	// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
	State *string `pulumi:"state"`
	// The key of the object type.
	TypeKey *string `pulumi:"typeKey"`
}

// A collection of values returned by getDataAssets.
type GetDataAssetsResult struct {
	// The data catalog's OCID.
	CatalogId string `pulumi:"catalogId"`
	// OCID of the user who created the data asset.
	CreatedById *string `pulumi:"createdById"`
	// The list of data_asset_collection.
	DataAssetCollections []GetDataAssetsDataAssetCollection `pulumi:"dataAssetCollections"`
	// A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName         *string `pulumi:"displayName"`
	DisplayNameContains *string `pulumi:"displayNameContains"`
	// External URI that can be used to reference the object. Format will differ based on the type of object.
	ExternalKey *string               `pulumi:"externalKey"`
	Fields      []string              `pulumi:"fields"`
	Filters     []GetDataAssetsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the data asset.
	State *string `pulumi:"state"`
	// The key of the object type. Type key's can be found via the '/types' endpoint.
	TypeKey *string `pulumi:"typeKey"`
}