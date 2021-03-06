// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Instance Console Connections in Oracle Cloud Infrastructure Core service.
//
// Lists the console connections for the specified compartment or instance.
//
// For more information about instance console connections, see [Troubleshooting Instances Using Instance Console Connections](https://docs.cloud.oracle.com/iaas/Content/Compute/References/serialconsole.htm).
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
// 		opt0 := oci_core_instance.Test_instance.Id
// 		_, err := oci.GetCoreInstanceConsoleConnections(ctx, &GetCoreInstanceConsoleConnectionsArgs{
// 			CompartmentId: _var.Compartment_id,
// 			InstanceId:    &opt0,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCoreInstanceConsoleConnections(ctx *pulumi.Context, args *GetCoreInstanceConsoleConnectionsArgs, opts ...pulumi.InvokeOption) (*GetCoreInstanceConsoleConnectionsResult, error) {
	var rv GetCoreInstanceConsoleConnectionsResult
	err := ctx.Invoke("oci:index/getCoreInstanceConsoleConnections:GetCoreInstanceConsoleConnections", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreInstanceConsoleConnections.
type GetCoreInstanceConsoleConnectionsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                                    `pulumi:"compartmentId"`
	Filters       []GetCoreInstanceConsoleConnectionsFilter `pulumi:"filters"`
	// The OCID of the instance.
	InstanceId *string `pulumi:"instanceId"`
}

// A collection of values returned by GetCoreInstanceConsoleConnections.
type GetCoreInstanceConsoleConnectionsResult struct {
	// The OCID of the compartment to contain the console connection.
	CompartmentId string                                    `pulumi:"compartmentId"`
	Filters       []GetCoreInstanceConsoleConnectionsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of instance_console_connections.
	InstanceConsoleConnections []GetCoreInstanceConsoleConnectionsInstanceConsoleConnection `pulumi:"instanceConsoleConnections"`
	// The OCID of the instance the console connection connects to.
	InstanceId *string `pulumi:"instanceId"`
}
