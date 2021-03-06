// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Vm Clusters in Oracle Cloud Infrastructure Database service.
//
// Lists the VM clusters in the specified compartment. Applies to Exadata Cloud@Customer instances only.
// To list the cloud VM clusters in an Exadata Cloud Service instance, use the [ListCloudVmClusters ](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudVmCluster/ListCloudVmClusters) operation.
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
// 		opt0 := _var.Vm_cluster_display_name
// 		opt1 := oci_database_exadata_infrastructure.Test_exadata_infrastructure.Id
// 		opt2 := _var.Vm_cluster_state
// 		_, err := oci.GetDatabaseVmClusters(ctx, &GetDatabaseVmClustersArgs{
// 			CompartmentId:           _var.Compartment_id,
// 			DisplayName:             &opt0,
// 			ExadataInfrastructureId: &opt1,
// 			State:                   &opt2,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDatabaseVmClusters(ctx *pulumi.Context, args *GetDatabaseVmClustersArgs, opts ...pulumi.InvokeOption) (*GetDatabaseVmClustersResult, error) {
	var rv GetDatabaseVmClustersResult
	err := ctx.Invoke("oci:index/getDatabaseVmClusters:GetDatabaseVmClusters", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetDatabaseVmClusters.
type GetDatabaseVmClustersArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string `pulumi:"displayName"`
	// If provided, filters the results for the given Exadata Infrastructure.
	ExadataInfrastructureId *string                       `pulumi:"exadataInfrastructureId"`
	Filters                 []GetDatabaseVmClustersFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
}

// A collection of values returned by GetDatabaseVmClusters.
type GetDatabaseVmClustersResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The user-friendly name for the Exadata Cloud@Customer VM cluster. The name does not need to be unique.
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
	ExadataInfrastructureId *string                       `pulumi:"exadataInfrastructureId"`
	Filters                 []GetDatabaseVmClustersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the VM cluster.
	State *string `pulumi:"state"`
	// The list of vm_clusters.
	VmClusters []GetDatabaseVmClustersVmCluster `pulumi:"vmClusters"`
}
