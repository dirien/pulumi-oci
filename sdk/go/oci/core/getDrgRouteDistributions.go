// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Drg Route Distributions in Oracle Cloud Infrastructure Core service.
//
// Lists the route distributions in the specified DRG.
//
// To retrieve the statements in a distribution, use the
// ListDrgRouteDistributionStatements operation.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/core"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Drg_route_distribution_display_name
// 		opt1 := _var.Drg_route_distribution_state
// 		_, err := core.GetDrgRouteDistributions(ctx, &core.GetDrgRouteDistributionsArgs{
// 			DrgId:       oci_core_drg.Test_drg.Id,
// 			DisplayName: &opt0,
// 			State:       &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDrgRouteDistributions(ctx *pulumi.Context, args *GetDrgRouteDistributionsArgs, opts ...pulumi.InvokeOption) (*GetDrgRouteDistributionsResult, error) {
	var rv GetDrgRouteDistributionsResult
	err := ctx.Invoke("oci:core/getDrgRouteDistributions:getDrgRouteDistributions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDrgRouteDistributions.
type GetDrgRouteDistributionsArgs struct {
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
	DrgId   string                           `pulumi:"drgId"`
	Filters []GetDrgRouteDistributionsFilter `pulumi:"filters"`
	// A filter that only returns resources that match the specified lifecycle state. The value is case insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getDrgRouteDistributions.
type GetDrgRouteDistributionsResult struct {
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG that contains this route distribution.
	DrgId string `pulumi:"drgId"`
	// The list of drg_route_distributions.
	DrgRouteDistributions []GetDrgRouteDistributionsDrgRouteDistribution `pulumi:"drgRouteDistributions"`
	Filters               []GetDrgRouteDistributionsFilter               `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The route distribution's current state.
	State *string `pulumi:"state"`
}
