// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package limits

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Quotas in Oracle Cloud Infrastructure Limits service.
//
// Lists all quotas on resources from the given compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/limits"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Quota_name
// 		opt1 := _var.Quota_state
// 		_, err := limits.GetQuotas(ctx, &limits.GetQuotasArgs{
// 			CompartmentId: _var.Tenancy_ocid,
// 			Name:          &opt0,
// 			State:         &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetQuotas(ctx *pulumi.Context, args *GetQuotasArgs, opts ...pulumi.InvokeOption) (*GetQuotasResult, error) {
	var rv GetQuotasResult
	err := ctx.Invoke("oci:limits/getQuotas:getQuotas", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getQuotas.
type GetQuotasArgs struct {
	// The OCID of the parent compartment (remember that the tenancy is simply the root compartment).
	CompartmentId string            `pulumi:"compartmentId"`
	Filters       []GetQuotasFilter `pulumi:"filters"`
	// name
	Name *string `pulumi:"name"`
	// Filters returned quotas based on the given state.
	State *string `pulumi:"state"`
}

// A collection of values returned by getQuotas.
type GetQuotasResult struct {
	// The OCID of the compartment containing the resource this quota applies to.
	CompartmentId string            `pulumi:"compartmentId"`
	Filters       []GetQuotasFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The name you assign to the quota during creation. The name must be unique across all quotas in the tenancy and cannot be changed.
	Name *string `pulumi:"name"`
	// The list of quotas.
	Quotas []GetQuotasQuota `pulumi:"quotas"`
	// The quota's current state.
	State *string `pulumi:"state"`
}