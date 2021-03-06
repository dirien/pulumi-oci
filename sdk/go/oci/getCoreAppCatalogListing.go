// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific App Catalog Listing resource in Oracle Cloud Infrastructure Core service.
//
// Gets the specified listing.
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
// 		_, err := oci.GetCoreAppCatalogListing(ctx, &GetCoreAppCatalogListingArgs{
// 			ListingId: data.Oci_core_app_catalog_listing.Test_listing.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCoreAppCatalogListing(ctx *pulumi.Context, args *GetCoreAppCatalogListingArgs, opts ...pulumi.InvokeOption) (*GetCoreAppCatalogListingResult, error) {
	var rv GetCoreAppCatalogListingResult
	err := ctx.Invoke("oci:index/getCoreAppCatalogListing:GetCoreAppCatalogListing", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreAppCatalogListing.
type GetCoreAppCatalogListingArgs struct {
	// The OCID of the listing.
	ListingId string `pulumi:"listingId"`
}

// A collection of values returned by GetCoreAppCatalogListing.
type GetCoreAppCatalogListingResult struct {
	// Listing's contact URL.
	ContactUrl string `pulumi:"contactUrl"`
	// Description of the listing.
	Description string `pulumi:"description"`
	// The display name of the listing.
	DisplayName string `pulumi:"displayName"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// the region free ocid of the listing resource.
	ListingId string `pulumi:"listingId"`
	// Publisher's logo URL.
	PublisherLogoUrl string `pulumi:"publisherLogoUrl"`
	// The name of the publisher who published this listing.
	PublisherName string `pulumi:"publisherName"`
	// The short summary for the listing.
	Summary string `pulumi:"summary"`
	// Date and time the listing was published, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
	TimePublished string `pulumi:"timePublished"`
}
