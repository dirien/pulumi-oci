// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Cost Tracking Tags in Oracle Cloud Infrastructure Identity service.
//
// Lists all the tags enabled for cost-tracking in the specified tenancy. For information about
// cost-tracking tags, see [Using Cost-tracking Tags](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/taggingoverview.htm#costs).
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
// 		_, err := identity.GetCostTrackingTags(ctx, &identity.GetCostTrackingTagsArgs{
// 			CompartmentId: _var.Compartment_id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCostTrackingTags(ctx *pulumi.Context, args *GetCostTrackingTagsArgs, opts ...pulumi.InvokeOption) (*GetCostTrackingTagsResult, error) {
	var rv GetCostTrackingTagsResult
	err := ctx.Invoke("oci:identity/getCostTrackingTags:getCostTrackingTags", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCostTrackingTags.
type GetCostTrackingTagsArgs struct {
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId string                      `pulumi:"compartmentId"`
	Filters       []GetCostTrackingTagsFilter `pulumi:"filters"`
}

// A collection of values returned by getCostTrackingTags.
type GetCostTrackingTagsResult struct {
	// The OCID of the compartment that contains the tag definition.
	CompartmentId string                      `pulumi:"compartmentId"`
	Filters       []GetCostTrackingTagsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of tags.
	Tags []GetCostTrackingTagsTag `pulumi:"tags"`
}
