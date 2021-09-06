// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Maintenance Run resource in Oracle Cloud Infrastructure Database service.
//
// Gets information about the specified maintenance run.
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
// 		_, err := database.LookupMaintenanceRun(ctx, &database.LookupMaintenanceRunArgs{
// 			MaintenanceRunId: oci_database_maintenance_run.Test_maintenance_run.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupMaintenanceRun(ctx *pulumi.Context, args *LookupMaintenanceRunArgs, opts ...pulumi.InvokeOption) (*LookupMaintenanceRunResult, error) {
	var rv LookupMaintenanceRunResult
	err := ctx.Invoke("oci:database/getMaintenanceRun:getMaintenanceRun", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMaintenanceRun.
type LookupMaintenanceRunArgs struct {
	// The maintenance run OCID.
	MaintenanceRunId string `pulumi:"maintenanceRunId"`
}

// A collection of values returned by getMaintenanceRun.
type LookupMaintenanceRunResult struct {
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Description of the maintenance run.
	Description string `pulumi:"description"`
	// The user-friendly name for the maintenance run.
	DisplayName string `pulumi:"displayName"`
	// The OCID of the maintenance run.
	Id                string `pulumi:"id"`
	IsEnabled         bool   `pulumi:"isEnabled"`
	IsPatchNowEnabled bool   `pulumi:"isPatchNowEnabled"`
	// Additional information about the current lifecycle state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	MaintenanceRunId string `pulumi:"maintenanceRunId"`
	// Maintenance sub-type.
	MaintenanceSubtype string `pulumi:"maintenanceSubtype"`
	// Maintenance type.
	MaintenanceType string `pulumi:"maintenanceType"`
	// Contain the patch failure count.
	PatchFailureCount int `pulumi:"patchFailureCount"`
	// The unique identifier of the patch. The identifier string includes the patch type, the Oracle Database version, and the patch creation date (using the format YYMMDD). For example, the identifier `ru_patch_19.9.0.0_201030` is used for an RU patch for Oracle Database 19.9.0.0 that was released October 30, 2020.
	PatchId string `pulumi:"patchId"`
	// Cloud Exadata infrastructure node patching method, either "ROLLING" or "NONROLLING". Default value is ROLLING.
	PatchingMode string `pulumi:"patchingMode"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance run for the Autonomous Data Guard association's peer container database.
	PeerMaintenanceRunId string `pulumi:"peerMaintenanceRunId"`
	// The current state of the maintenance run. For Autonomous Database on shared Exadata infrastructure, valid states are IN_PROGRESS, SUCCEEDED and FAILED.
	State string `pulumi:"state"`
	// The ID of the target resource on which the maintenance run occurs.
	TargetResourceId string `pulumi:"targetResourceId"`
	// The type of the target resource on which the maintenance run occurs.
	TargetResourceType string `pulumi:"targetResourceType"`
	// The date and time the maintenance run was completed.
	TimeEnded string `pulumi:"timeEnded"`
	// The date and time the maintenance run is scheduled to occur.
	TimeScheduled string `pulumi:"timeScheduled"`
	// The date and time the maintenance run starts.
	TimeStarted string `pulumi:"timeStarted"`
}
