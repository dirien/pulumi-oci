// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Listing Taxes in Oracle Cloud Infrastructure Marketplace service.
//
// Returns list of all tax implications that current tenant may be liable to once they launch the listing.
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
// 		opt0 := _var.Compartment_id
// 		_, err := oci.GetMarketplaceListingTaxes(ctx, &GetMarketplaceListingTaxesArgs{
// 			ListingId:     oci_marketplace_listing.Test_listing.Id,
// 			CompartmentId: &opt0,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetMarketplaceListingTaxes(ctx *pulumi.Context, args *GetMarketplaceListingTaxesArgs, opts ...pulumi.InvokeOption) (*GetMarketplaceListingTaxesResult, error) {
	var rv GetMarketplaceListingTaxesResult
	err := ctx.Invoke("oci:index/getMarketplaceListingTaxes:GetMarketplaceListingTaxes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetMarketplaceListingTaxes.
type GetMarketplaceListingTaxesArgs struct {
	// The unique identifier for the compartment.
	CompartmentId *string                            `pulumi:"compartmentId"`
	Filters       []GetMarketplaceListingTaxesFilter `pulumi:"filters"`
	// The unique identifier for the listing.
	ListingId string `pulumi:"listingId"`
}

// A collection of values returned by GetMarketplaceListingTaxes.
type GetMarketplaceListingTaxesResult struct {
	CompartmentId *string                            `pulumi:"compartmentId"`
	Filters       []GetMarketplaceListingTaxesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id        string `pulumi:"id"`
	ListingId string `pulumi:"listingId"`
	// The list of taxes.
	Taxes []GetMarketplaceListingTaxesTax `pulumi:"taxes"`
}
