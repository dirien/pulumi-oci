// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Ip Sec Connection Device Status resource in Oracle Cloud Infrastructure Core service.
//
// Deprecated. To get the tunnel status, instead use
// [GetIPSecConnectionTunnel](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnectionTunnel/GetIPSecConnectionTunnel).
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
// 		_, err := oci.GetCoreIpsecStatus(ctx, &GetCoreIpsecStatusArgs{
// 			IpsecId: oci_core_ipsec.Test_ipsec.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCoreIpsecStatus(ctx *pulumi.Context, args *GetCoreIpsecStatusArgs, opts ...pulumi.InvokeOption) (*GetCoreIpsecStatusResult, error) {
	var rv GetCoreIpsecStatusResult
	err := ctx.Invoke("oci:index/getCoreIpsecStatus:GetCoreIpsecStatus", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreIpsecStatus.
type GetCoreIpsecStatusArgs struct {
	Filters []GetCoreIpsecStatusFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the IPSec connection.
	IpsecId string `pulumi:"ipsecId"`
}

// A collection of values returned by GetCoreIpsecStatus.
type GetCoreIpsecStatusResult struct {
	// The OCID of the compartment containing the IPSec connection.
	CompartmentId string                     `pulumi:"compartmentId"`
	Filters       []GetCoreIpsecStatusFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id      string `pulumi:"id"`
	IpsecId string `pulumi:"ipsecId"`
	// The date and time the IPSec connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// Two [TunnelStatus](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelStatus/) objects.
	Tunnels []GetCoreIpsecStatusTunnel `pulumi:"tunnels"`
}
