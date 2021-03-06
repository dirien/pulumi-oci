// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Boot Volume Replicas in Oracle Cloud Infrastructure Core service.
//
// Lists the boot volume replicas in the specified compartment and availability domain.
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
// 		opt0 := _var.Boot_volume_replica_display_name
// 		opt1 := _var.Boot_volume_replica_state
// 		_, err := oci.GetCoreBootVolumeReplicas(ctx, &GetCoreBootVolumeReplicasArgs{
// 			AvailabilityDomain: _var.Boot_volume_replica_availability_domain,
// 			CompartmentId:      _var.Compartment_id,
// 			DisplayName:        &opt0,
// 			State:              &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCoreBootVolumeReplicas(ctx *pulumi.Context, args *GetCoreBootVolumeReplicasArgs, opts ...pulumi.InvokeOption) (*GetCoreBootVolumeReplicasResult, error) {
	var rv GetCoreBootVolumeReplicasResult
	err := ctx.Invoke("oci:index/getCoreBootVolumeReplicas:GetCoreBootVolumeReplicas", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreBootVolumeReplicas.
type GetCoreBootVolumeReplicasArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string                           `pulumi:"displayName"`
	Filters     []GetCoreBootVolumeReplicasFilter `pulumi:"filters"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by GetCoreBootVolumeReplicas.
type GetCoreBootVolumeReplicasResult struct {
	// The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The list of boot_volume_replicas.
	BootVolumeReplicas []GetCoreBootVolumeReplicasBootVolumeReplica `pulumi:"bootVolumeReplicas"`
	// The OCID of the compartment that contains the boot volume replica.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                           `pulumi:"displayName"`
	Filters     []GetCoreBootVolumeReplicasFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of a boot volume replica.
	State *string `pulumi:"state"`
}
