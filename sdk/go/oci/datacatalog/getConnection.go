// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package datacatalog

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Connection resource in Oracle Cloud Infrastructure Data Catalog service.
//
// Gets a specific data asset connection by key.
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
// 		_, err := datacatalog.LookupConnection(ctx, &datacatalog.LookupConnectionArgs{
// 			CatalogId:     oci_datacatalog_catalog.Test_catalog.Id,
// 			ConnectionKey: _var.Connection_connection_key,
// 			DataAssetKey:  _var.Connection_data_asset_key,
// 			Fields:        _var.Connection_fields,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupConnection(ctx *pulumi.Context, args *LookupConnectionArgs, opts ...pulumi.InvokeOption) (*LookupConnectionResult, error) {
	var rv LookupConnectionResult
	err := ctx.Invoke("oci:datacatalog/getConnection:getConnection", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getConnection.
type LookupConnectionArgs struct {
	// Unique catalog identifier.
	CatalogId string `pulumi:"catalogId"`
	// Unique connection key.
	ConnectionKey string `pulumi:"connectionKey"`
	// Unique data asset key.
	DataAssetKey string `pulumi:"dataAssetKey"`
	// Specifies the fields to return in a connection response.
	Fields []string `pulumi:"fields"`
}

// A collection of values returned by getConnection.
type LookupConnectionResult struct {
	CatalogId     string `pulumi:"catalogId"`
	ConnectionKey string `pulumi:"connectionKey"`
	// OCID of the user who created the connection.
	CreatedById string `pulumi:"createdById"`
	// Unique key of the parent data asset.
	DataAssetKey string `pulumi:"dataAssetKey"`
	// A description of the connection.
	Description string `pulumi:"description"`
	// A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName   string                 `pulumi:"displayName"`
	EncProperties map[string]interface{} `pulumi:"encProperties"`
	// Unique external key of this object from the source system.
	ExternalKey string   `pulumi:"externalKey"`
	Fields      []string `pulumi:"fields"`
	Id          string   `pulumi:"id"`
	// Indicates whether this connection is the default connection.
	IsDefault bool `pulumi:"isDefault"`
	// Unique connection key that is immutable.
	Key string `pulumi:"key"`
	// A map of maps that contains the properties which are specific to the connection type. Each connection type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most connections have required properties within the "default" category. Example: `{"properties": { "default": { "username": "user1"}}}`
	Properties map[string]interface{} `pulumi:"properties"`
	// The current state of the connection.
	State string `pulumi:"state"`
	// The date and time the connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// Time that the connections status was last updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeStatusUpdated string `pulumi:"timeStatusUpdated"`
	// The last time that any change was made to the connection. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeUpdated string `pulumi:"timeUpdated"`
	// The key of the object type. Type key's can be found via the '/types' endpoint.
	TypeKey string `pulumi:"typeKey"`
	// OCID of the user who modified the connection.
	UpdatedById string `pulumi:"updatedById"`
	// URI to the connection instance in the API.
	Uri string `pulumi:"uri"`
}
