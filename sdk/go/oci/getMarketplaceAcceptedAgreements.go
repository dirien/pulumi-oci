// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Accepted Agreements in Oracle Cloud Infrastructure Marketplace service.
//
// Lists the terms of use agreements that have been accepted in the specified compartment.
// You can filter results by specifying query parameters.
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
// 		opt0 := oci_marketplace_accepted_agreement.Test_accepted_agreement.Id
// 		opt1 := _var.Accepted_agreement_display_name
// 		opt2 := oci_marketplace_listing.Test_listing.Id
// 		opt3 := _var.Accepted_agreement_package_version
// 		_, err := oci.GetMarketplaceAcceptedAgreements(ctx, &GetMarketplaceAcceptedAgreementsArgs{
// 			CompartmentId:       _var.Compartment_id,
// 			AcceptedAgreementId: &opt0,
// 			DisplayName:         &opt1,
// 			ListingId:           &opt2,
// 			PackageVersion:      &opt3,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetMarketplaceAcceptedAgreements(ctx *pulumi.Context, args *GetMarketplaceAcceptedAgreementsArgs, opts ...pulumi.InvokeOption) (*GetMarketplaceAcceptedAgreementsResult, error) {
	var rv GetMarketplaceAcceptedAgreementsResult
	err := ctx.Invoke("oci:index/getMarketplaceAcceptedAgreements:GetMarketplaceAcceptedAgreements", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetMarketplaceAcceptedAgreements.
type GetMarketplaceAcceptedAgreementsArgs struct {
	// The unique identifier for the accepted terms of use agreement.
	AcceptedAgreementId *string `pulumi:"acceptedAgreementId"`
	// The unique identifier for the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The display name of the resource.
	DisplayName *string                                  `pulumi:"displayName"`
	Filters     []GetMarketplaceAcceptedAgreementsFilter `pulumi:"filters"`
	// The unique identifier for the listing.
	ListingId *string `pulumi:"listingId"`
	// The version of the package. Package versions are unique within a listing.
	PackageVersion *string `pulumi:"packageVersion"`
}

// A collection of values returned by GetMarketplaceAcceptedAgreements.
type GetMarketplaceAcceptedAgreementsResult struct {
	AcceptedAgreementId *string `pulumi:"acceptedAgreementId"`
	// The list of accepted_agreements.
	AcceptedAgreements []GetMarketplaceAcceptedAgreementsAcceptedAgreement `pulumi:"acceptedAgreements"`
	// The unique identifier for the compartment where the agreement was accepted.
	CompartmentId string `pulumi:"compartmentId"`
	// A display name for the accepted agreement.
	DisplayName *string                                  `pulumi:"displayName"`
	Filters     []GetMarketplaceAcceptedAgreementsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The unique identifier for the listing associated with the agreement.
	ListingId *string `pulumi:"listingId"`
	// The package version associated with the agreement.
	PackageVersion *string `pulumi:"packageVersion"`
}
