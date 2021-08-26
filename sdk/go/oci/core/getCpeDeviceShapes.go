// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Cpe Device Shapes in Oracle Cloud Infrastructure Core service.
//
// Lists the CPE device types that the Networking service provides CPE configuration
// content for (example: Cisco ASA). The content helps a network engineer configure
// the actual CPE device represented by a [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object.
//
// If you want to generate CPE configuration content for one of the returned CPE device types,
// ensure that the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object's `cpeDeviceShapeId` attribute is set
// to the CPE device type's [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) (returned by this operation).
//
// For information about generating CPE configuration content, see these operations:
//
//   * [GetCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/GetCpeDeviceConfigContent)
//   * [GetIpsecCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/GetIpsecCpeDeviceConfigContent)
//   * [GetTunnelCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelCpeDeviceConfig/GetTunnelCpeDeviceConfigContent)
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
// 		_, err := core.GetCpeDeviceShapes(ctx, nil, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCpeDeviceShapes(ctx *pulumi.Context, args *GetCpeDeviceShapesArgs, opts ...pulumi.InvokeOption) (*GetCpeDeviceShapesResult, error) {
	var rv GetCpeDeviceShapesResult
	err := ctx.Invoke("oci:core/getCpeDeviceShapes:getCpeDeviceShapes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCpeDeviceShapes.
type GetCpeDeviceShapesArgs struct {
	Filters []GetCpeDeviceShapesFilter `pulumi:"filters"`
}

// A collection of values returned by getCpeDeviceShapes.
type GetCpeDeviceShapesResult struct {
	// The list of cpe_device_shapes.
	CpeDeviceShapes []GetCpeDeviceShapesCpeDeviceShape `pulumi:"cpeDeviceShapes"`
	Filters         []GetCpeDeviceShapesFilter         `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}