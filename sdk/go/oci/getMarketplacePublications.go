// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Publications in Oracle Cloud Infrastructure Marketplace service.
//
// Lists the publications in the given compartment
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
// 		opt0 := oci_marketplace_publication.Test_publication.Id
// 		_, err := oci.GetMarketplacePublications(ctx, &GetMarketplacePublicationsArgs{
// 			CompartmentId:    _var.Compartment_id,
// 			ListingType:      _var.Publication_listing_type,
// 			Names:            _var.Publication_name,
// 			OperatingSystems: _var.Publication_operating_systems,
// 			PublicationId:    &opt0,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetMarketplacePublications(ctx *pulumi.Context, args *GetMarketplacePublicationsArgs, opts ...pulumi.InvokeOption) (*GetMarketplacePublicationsResult, error) {
	var rv GetMarketplacePublicationsResult
	err := ctx.Invoke("oci:index/getMarketplacePublications:GetMarketplacePublications", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetMarketplacePublications.
type GetMarketplacePublicationsArgs struct {
	// The unique identifier for the compartment.
	CompartmentId string                             `pulumi:"compartmentId"`
	Filters       []GetMarketplacePublicationsFilter `pulumi:"filters"`
	// The type of the listing
	ListingType string `pulumi:"listingType"`
	// The name of the listing.
	Names []string `pulumi:"names"`
	// OS of the listing.
	OperatingSystems []string `pulumi:"operatingSystems"`
	// The unique identifier for the listing.
	PublicationId *string `pulumi:"publicationId"`
}

// A collection of values returned by GetMarketplacePublications.
type GetMarketplacePublicationsResult struct {
	// The Compartment id where the listings exists
	CompartmentId string                             `pulumi:"compartmentId"`
	Filters       []GetMarketplacePublicationsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// In which catalog the listing should exist.
	ListingType string `pulumi:"listingType"`
	// name of the operating system
	Names            []string `pulumi:"names"`
	OperatingSystems []string `pulumi:"operatingSystems"`
	PublicationId    *string  `pulumi:"publicationId"`
	// The list of publications.
	Publications []GetMarketplacePublicationsPublication `pulumi:"publications"`
}