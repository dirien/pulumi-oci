// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Cpes in Oracle Cloud Infrastructure Core service.
//
// Lists the customer-premises equipment objects (CPEs) in the specified compartment.
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
// 		_, err := core.GetCpes(ctx, &core.GetCpesArgs{
// 			CompartmentId: _var.Compartment_id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCpes(ctx *pulumi.Context, args *GetCpesArgs, opts ...pulumi.InvokeOption) (*GetCpesResult, error) {
	var rv GetCpesResult
	err := ctx.Invoke("oci:core/getCpes:getCpes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCpes.
type GetCpesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string          `pulumi:"compartmentId"`
	Filters       []GetCpesFilter `pulumi:"filters"`
}

// A collection of values returned by getCpes.
type GetCpesResult struct {
	// The OCID of the compartment containing the CPE.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of cpes.
	Cpes    []GetCpesCpe    `pulumi:"cpes"`
	Filters []GetCpesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}
