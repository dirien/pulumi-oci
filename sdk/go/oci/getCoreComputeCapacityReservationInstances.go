// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Compute Capacity Reservation Instances in Oracle Cloud Infrastructure Core service.
//
// Lists the instances launched under a capacity reservation. You can filter results by specifying criteria.
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
// 		opt0 := _var.Compute_capacity_reservation_instance_availability_domain
// 		opt1 := _var.Compartment_id
// 		_, err := oci.GetCoreComputeCapacityReservationInstances(ctx, &GetCoreComputeCapacityReservationInstancesArgs{
// 			CapacityReservationId: oci_core_capacity_reservation.Test_capacity_reservation.Id,
// 			AvailabilityDomain:    &opt0,
// 			CompartmentId:         &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCoreComputeCapacityReservationInstances(ctx *pulumi.Context, args *GetCoreComputeCapacityReservationInstancesArgs, opts ...pulumi.InvokeOption) (*GetCoreComputeCapacityReservationInstancesResult, error) {
	var rv GetCoreComputeCapacityReservationInstancesResult
	err := ctx.Invoke("oci:index/getCoreComputeCapacityReservationInstances:GetCoreComputeCapacityReservationInstances", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetCoreComputeCapacityReservationInstances.
type GetCoreComputeCapacityReservationInstancesArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The OCID of the compute capacity reservation.
	CapacityReservationId string `pulumi:"capacityReservationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string                                            `pulumi:"compartmentId"`
	Filters       []GetCoreComputeCapacityReservationInstancesFilter `pulumi:"filters"`
}

// A collection of values returned by GetCoreComputeCapacityReservationInstances.
type GetCoreComputeCapacityReservationInstancesResult struct {
	// The availability domain the instance is running in.
	AvailabilityDomain    *string `pulumi:"availabilityDomain"`
	CapacityReservationId string  `pulumi:"capacityReservationId"`
	// The list of capacity_reservation_instances.
	CapacityReservationInstances []GetCoreComputeCapacityReservationInstancesCapacityReservationInstance `pulumi:"capacityReservationInstances"`
	// The OCID of the compartment that contains the instance.
	CompartmentId *string                                            `pulumi:"compartmentId"`
	Filters       []GetCoreComputeCapacityReservationInstancesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}
