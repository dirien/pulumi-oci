// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Publishers in Oracle Cloud Infrastructure Marketplace service.
//
// Gets the list of all the publishers of listings available in Oracle Cloud Infrastructure Marketplace.
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
// 		opt1 := oci_marketplace_publisher.Test_publisher.Id
// 		_, err := oci.GetMarketplacePublishers(ctx, &GetMarketplacePublishersArgs{
// 			CompartmentId: &opt0,
// 			PublisherId:   &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetMarketplacePublishers(ctx *pulumi.Context, args *GetMarketplacePublishersArgs, opts ...pulumi.InvokeOption) (*GetMarketplacePublishersResult, error) {
	var rv GetMarketplacePublishersResult
	err := ctx.Invoke("oci:index/getMarketplacePublishers:GetMarketplacePublishers", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetMarketplacePublishers.
type GetMarketplacePublishersArgs struct {
	// The unique identifier for the compartment.
	CompartmentId *string                          `pulumi:"compartmentId"`
	Filters       []GetMarketplacePublishersFilter `pulumi:"filters"`
	// Limit results to just this publisher.
	PublisherId *string `pulumi:"publisherId"`
}

// A collection of values returned by GetMarketplacePublishers.
type GetMarketplacePublishersResult struct {
	CompartmentId *string                          `pulumi:"compartmentId"`
	Filters       []GetMarketplacePublishersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id          string  `pulumi:"id"`
	PublisherId *string `pulumi:"publisherId"`
	// The list of publishers.
	Publishers []GetMarketplacePublishersPublisher `pulumi:"publishers"`
}
