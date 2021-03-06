// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Network Security Group Vnics in Oracle Cloud Infrastructure Core service.
//
// Lists the VNICs in the specified network security group.
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
// 		_, err := oci.GetCoreNetworkSecurityGroupVnics(ctx, &GetCoreNetworkSecurityGroupVnicsArgs{
// 			NetworkSecurityGroupId: oci_core_network_security_group.Test_network_security_group.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCoreNetworkSecurityGroupVnics(ctx *pulumi.Context, args *GetCoreNetworkSecurityGroupVnicsArgs, opts ...pulumi.InvokeOption) (*GetCoreNetworkSecurityGroupVnicsResult, error) {
	var rv GetCoreNetworkSecurityGroupVnicsResult
	err := ctx.Invoke("oci:index/getCoreNetworkSecurityGroupVnics:GetCoreNetworkSecurityGroupVnics", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreNetworkSecurityGroupVnics.
type GetCoreNetworkSecurityGroupVnicsArgs struct {
	Filters []GetCoreNetworkSecurityGroupVnicsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
	NetworkSecurityGroupId string `pulumi:"networkSecurityGroupId"`
}

// A collection of values returned by GetCoreNetworkSecurityGroupVnics.
type GetCoreNetworkSecurityGroupVnicsResult struct {
	Filters []GetCoreNetworkSecurityGroupVnicsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                     string `pulumi:"id"`
	NetworkSecurityGroupId string `pulumi:"networkSecurityGroupId"`
	// The list of network_security_group_vnics.
	NetworkSecurityGroupVnics []GetCoreNetworkSecurityGroupVnicsNetworkSecurityGroupVnic `pulumi:"networkSecurityGroupVnics"`
}
