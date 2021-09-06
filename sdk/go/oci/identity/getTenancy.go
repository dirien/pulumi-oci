// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Tenancy resource in Oracle Cloud Infrastructure Identity service.
//
// Get the specified tenancy's information.
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
// 		_, err := identity.GetTenancy(ctx, &identity.GetTenancyArgs{
// 			TenancyId: _var.Tenancy_ocid,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetTenancy(ctx *pulumi.Context, args *GetTenancyArgs, opts ...pulumi.InvokeOption) (*GetTenancyResult, error) {
	var rv GetTenancyResult
	err := ctx.Invoke("oci:identity/getTenancy:getTenancy", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getTenancy.
type GetTenancyArgs struct {
	// The OCID of the tenancy.
	TenancyId string `pulumi:"tenancyId"`
}

// A collection of values returned by getTenancy.
type GetTenancyResult struct {
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The description of the tenancy.
	Description string `pulumi:"description"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The region key for the tenancy's home region. For the full list of supported regions, see [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm).  Example: `PHX`
	HomeRegionKey string `pulumi:"homeRegionKey"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The name of the tenancy.
	Name      string `pulumi:"name"`
	TenancyId string `pulumi:"tenancyId"`
	// Url which refers to the UPI IDCS compatibility layer endpoint configured for this Tenant's home region.
	UpiIdcsCompatibilityLayerEndpoint string `pulumi:"upiIdcsCompatibilityLayerEndpoint"`
}
