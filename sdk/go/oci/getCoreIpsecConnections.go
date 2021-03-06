// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Ip Sec Connections in Oracle Cloud Infrastructure Core service.
//
// Lists the IPSec connections for the specified compartment. You can filter the
// results by DRG or CPE.
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
// 		opt0 := oci_core_cpe.Test_cpe.Id
// 		opt1 := oci_core_drg.Test_drg.Id
// 		_, err := oci.GetCoreIpsecConnections(ctx, &GetCoreIpsecConnectionsArgs{
// 			CompartmentId: _var.Compartment_id,
// 			CpeId:         &opt0,
// 			DrgId:         &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCoreIpsecConnections(ctx *pulumi.Context, args *GetCoreIpsecConnectionsArgs, opts ...pulumi.InvokeOption) (*GetCoreIpsecConnectionsResult, error) {
	var rv GetCoreIpsecConnectionsResult
	err := ctx.Invoke("oci:index/getCoreIpsecConnections:GetCoreIpsecConnections", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreIpsecConnections.
type GetCoreIpsecConnectionsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CPE.
	CpeId *string `pulumi:"cpeId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
	DrgId   *string                         `pulumi:"drgId"`
	Filters []GetCoreIpsecConnectionsFilter `pulumi:"filters"`
}

// A collection of values returned by GetCoreIpsecConnections.
type GetCoreIpsecConnectionsResult struct {
	// The OCID of the compartment containing the IPSec connection.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of connections.
	Connections []GetCoreIpsecConnectionsConnection `pulumi:"connections"`
	// The OCID of the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object.
	CpeId *string `pulumi:"cpeId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
	DrgId   *string                         `pulumi:"drgId"`
	Filters []GetCoreIpsecConnectionsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}
