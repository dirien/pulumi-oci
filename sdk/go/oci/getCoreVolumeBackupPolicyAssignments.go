// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Volume Backup Policy Assignments in Oracle Cloud Infrastructure Core service.
//
// Gets the volume backup policy assignment for the specified volume. The
// `assetId` query parameter is required, and the returned list will contain at most
// one item, since volume can only have one volume backup policy assigned at a time.
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
// 		_, err := oci.GetCoreVolumeBackupPolicyAssignments(ctx, &GetCoreVolumeBackupPolicyAssignmentsArgs{
// 			AssetId: oci_core_volume.Test_volume.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCoreVolumeBackupPolicyAssignments(ctx *pulumi.Context, args *GetCoreVolumeBackupPolicyAssignmentsArgs, opts ...pulumi.InvokeOption) (*GetCoreVolumeBackupPolicyAssignmentsResult, error) {
	var rv GetCoreVolumeBackupPolicyAssignmentsResult
	err := ctx.Invoke("oci:index/getCoreVolumeBackupPolicyAssignments:GetCoreVolumeBackupPolicyAssignments", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreVolumeBackupPolicyAssignments.
type GetCoreVolumeBackupPolicyAssignmentsArgs struct {
	// The OCID of an asset (e.g. a volume).
	AssetId string                                       `pulumi:"assetId"`
	Filters []GetCoreVolumeBackupPolicyAssignmentsFilter `pulumi:"filters"`
}

// A collection of values returned by GetCoreVolumeBackupPolicyAssignments.
type GetCoreVolumeBackupPolicyAssignmentsResult struct {
	// The OCID of the volume the policy has been assigned to.
	AssetId string                                       `pulumi:"assetId"`
	Filters []GetCoreVolumeBackupPolicyAssignmentsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of volume_backup_policy_assignments.
	VolumeBackupPolicyAssignments []GetCoreVolumeBackupPolicyAssignmentsVolumeBackupPolicyAssignment `pulumi:"volumeBackupPolicyAssignments"`
}