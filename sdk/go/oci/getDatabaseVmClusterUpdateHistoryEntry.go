// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Vm Cluster Update History Entry resource in Oracle Cloud Infrastructure Database service.
//
// Gets the maintenance update history details for the specified update history entry. Applies to Exadata Cloud@Customer instances only.
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
// 		_, err := oci.GetDatabaseVmClusterUpdateHistoryEntry(ctx, &GetDatabaseVmClusterUpdateHistoryEntryArgs{
// 			UpdateHistoryEntryId: oci_database_update_history_entry.Test_update_history_entry.Id,
// 			VmClusterId:          oci_database_vm_cluster.Test_vm_cluster.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDatabaseVmClusterUpdateHistoryEntry(ctx *pulumi.Context, args *GetDatabaseVmClusterUpdateHistoryEntryArgs, opts ...pulumi.InvokeOption) (*GetDatabaseVmClusterUpdateHistoryEntryResult, error) {
	var rv GetDatabaseVmClusterUpdateHistoryEntryResult
	err := ctx.Invoke("oci:index/getDatabaseVmClusterUpdateHistoryEntry:GetDatabaseVmClusterUpdateHistoryEntry", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetDatabaseVmClusterUpdateHistoryEntry.
type GetDatabaseVmClusterUpdateHistoryEntryArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance update history entry.
	UpdateHistoryEntryId string `pulumi:"updateHistoryEntryId"`
	// The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	VmClusterId string `pulumi:"vmClusterId"`
}

// A collection of values returned by GetDatabaseVmClusterUpdateHistoryEntry.
type GetDatabaseVmClusterUpdateHistoryEntryResult struct {
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Descriptive text providing additional details about the lifecycle state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The current lifecycle state of the maintenance update operation.
	State string `pulumi:"state"`
	// The date and time when the maintenance update action completed.
	TimeCompleted string `pulumi:"timeCompleted"`
	// The date and time when the maintenance update action started.
	TimeStarted string `pulumi:"timeStarted"`
	// The update action performed using this maintenance update.
	UpdateAction         string `pulumi:"updateAction"`
	UpdateHistoryEntryId string `pulumi:"updateHistoryEntryId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance update.
	UpdateId string `pulumi:"updateId"`
	// The type of VM cluster maintenance update.
	UpdateType  string `pulumi:"updateType"`
	VmClusterId string `pulumi:"vmClusterId"`
}
