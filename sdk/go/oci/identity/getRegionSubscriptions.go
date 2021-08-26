// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Region Subscriptions in Oracle Cloud Infrastructure Identity service.
//
// Lists the region subscriptions for the specified tenancy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/identity"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := identity.GetRegionSubscriptions(ctx, &identity.GetRegionSubscriptionsArgs{
// 			TenancyId: oci_identity_tenancy.Test_tenancy.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetRegionSubscriptions(ctx *pulumi.Context, args *GetRegionSubscriptionsArgs, opts ...pulumi.InvokeOption) (*GetRegionSubscriptionsResult, error) {
	var rv GetRegionSubscriptionsResult
	err := ctx.Invoke("oci:identity/getRegionSubscriptions:getRegionSubscriptions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRegionSubscriptions.
type GetRegionSubscriptionsArgs struct {
	Filters []GetRegionSubscriptionsFilter `pulumi:"filters"`
	// The OCID of the tenancy.
	TenancyId string `pulumi:"tenancyId"`
}

// A collection of values returned by getRegionSubscriptions.
type GetRegionSubscriptionsResult struct {
	Filters []GetRegionSubscriptionsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of region_subscriptions.
	RegionSubscriptions []GetRegionSubscriptionsRegionSubscription `pulumi:"regionSubscriptions"`
	TenancyId           string                                     `pulumi:"tenancyId"`
}