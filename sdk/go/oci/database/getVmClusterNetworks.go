// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Vm Cluster Networks in Oracle Cloud Infrastructure Database service.
//
// Gets a list of the VM cluster networks in the specified compartment. Applies to Exadata Cloud@Customer instances only.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/database"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Vm_cluster_network_display_name
// 		opt1 := _var.Vm_cluster_network_state
// 		_, err := database.GetVmClusterNetworks(ctx, &database.GetVmClusterNetworksArgs{
// 			CompartmentId:           _var.Compartment_id,
// 			ExadataInfrastructureId: oci_database_exadata_infrastructure.Test_exadata_infrastructure.Id,
// 			DisplayName:             &opt0,
// 			State:                   &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetVmClusterNetworks(ctx *pulumi.Context, args *GetVmClusterNetworksArgs, opts ...pulumi.InvokeOption) (*GetVmClusterNetworksResult, error) {
	var rv GetVmClusterNetworksResult
	err := ctx.Invoke("oci:database/getVmClusterNetworks:getVmClusterNetworks", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVmClusterNetworks.
type GetVmClusterNetworksArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string `pulumi:"displayName"`
	// The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ExadataInfrastructureId string                       `pulumi:"exadataInfrastructureId"`
	Filters                 []GetVmClusterNetworksFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
}

// A collection of values returned by getVmClusterNetworks.
type GetVmClusterNetworksResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The user-friendly name for the VM cluster network. The name does not need to be unique.
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
	ExadataInfrastructureId string                       `pulumi:"exadataInfrastructureId"`
	Filters                 []GetVmClusterNetworksFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the VM cluster network.
	State *string `pulumi:"state"`
	// The list of vm_cluster_networks.
	VmClusterNetworks []GetVmClusterNetworksVmClusterNetwork `pulumi:"vmClusterNetworks"`
}
