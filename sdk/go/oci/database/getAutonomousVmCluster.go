// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Autonomous Vm Cluster resource in Oracle Cloud Infrastructure Database service.
//
// Gets information about the specified Autonomous VM cluster for an Exadata Cloud@Customer system.
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
// 		_, err := database.LookupAutonomousVmCluster(ctx, &database.LookupAutonomousVmClusterArgs{
// 			AutonomousVmClusterId: oci_database_autonomous_vm_cluster.Test_autonomous_vm_cluster.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupAutonomousVmCluster(ctx *pulumi.Context, args *LookupAutonomousVmClusterArgs, opts ...pulumi.InvokeOption) (*LookupAutonomousVmClusterResult, error) {
	var rv LookupAutonomousVmClusterResult
	err := ctx.Invoke("oci:database/getAutonomousVmCluster:getAutonomousVmCluster", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutonomousVmCluster.
type LookupAutonomousVmClusterArgs struct {
	// The autonomous VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousVmClusterId string `pulumi:"autonomousVmClusterId"`
}

// A collection of values returned by getAutonomousVmCluster.
type LookupAutonomousVmClusterResult struct {
	AutonomousVmClusterId string `pulumi:"autonomousVmClusterId"`
	// The numnber of CPU cores available.
	AvailableCpus int `pulumi:"availableCpus"`
	// The data storage available in TBs
	AvailableDataStorageSizeInTbs float64 `pulumi:"availableDataStorageSizeInTbs"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The number of enabled CPU cores.
	CpusEnabled int `pulumi:"cpusEnabled"`
	// The total data storage allocated in TBs
	DataStorageSizeInTbs float64 `pulumi:"dataStorageSizeInTbs"`
	// The local node storage allocated in GBs.
	DbNodeStorageSizeInGbs int `pulumi:"dbNodeStorageSizeInGbs"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The user-friendly name for the Autonomous VM cluster. The name does not need to be unique.
	DisplayName string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
	ExadataInfrastructureId string `pulumi:"exadataInfrastructureId"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous VM cluster.
	Id string `pulumi:"id"`
	// If true, database backup on local Exadata storage is configured for the Autonomous VM cluster. If false, database backup on local Exadata storage is not available in the Autonomous VM cluster.
	IsLocalBackupEnabled bool `pulumi:"isLocalBackupEnabled"`
	// The Oracle license model that applies to the Autonomous VM cluster. The default is LICENSE_INCLUDED.
	LicenseModel string `pulumi:"licenseModel"`
	// Additional information about the current lifecycle state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The memory allocated in GBs.
	MemorySizeInGbs int `pulumi:"memorySizeInGbs"`
	// The current state of the Autonomous VM cluster.
	State string `pulumi:"state"`
	// The date and time that the Autonomous VM cluster was created.
	TimeCreated string `pulumi:"timeCreated"`
	// The time zone to use for the Autonomous VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
	TimeZone string `pulumi:"timeZone"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
	VmClusterNetworkId string `pulumi:"vmClusterNetworkId"`
}
