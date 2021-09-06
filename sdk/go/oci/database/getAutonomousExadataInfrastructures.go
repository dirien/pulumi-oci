// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Autonomous Exadata Infrastructures in Oracle Cloud Infrastructure Database service.
//
// Gets a list of the Autonomous Exadata Infrastructures in the specified compartment.
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
// 		opt0 := _var.Autonomous_exadata_infrastructure_availability_domain
// 		opt1 := _var.Autonomous_exadata_infrastructure_display_name
// 		opt2 := _var.Autonomous_exadata_infrastructure_state
// 		_, err := database.GetAutonomousExadataInfrastructures(ctx, &database.GetAutonomousExadataInfrastructuresArgs{
// 			CompartmentId:      _var.Compartment_id,
// 			AvailabilityDomain: &opt0,
// 			DisplayName:        &opt1,
// 			State:              &opt2,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetAutonomousExadataInfrastructures(ctx *pulumi.Context, args *GetAutonomousExadataInfrastructuresArgs, opts ...pulumi.InvokeOption) (*GetAutonomousExadataInfrastructuresResult, error) {
	var rv GetAutonomousExadataInfrastructuresResult
	err := ctx.Invoke("oci:database/getAutonomousExadataInfrastructures:getAutonomousExadataInfrastructures", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutonomousExadataInfrastructures.
type GetAutonomousExadataInfrastructuresArgs struct {
	// A filter to return only resources that match the given availability domain exactly.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string                                     `pulumi:"displayName"`
	Filters     []GetAutonomousExadataInfrastructuresFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
}

// A collection of values returned by getAutonomousExadataInfrastructures.
type GetAutonomousExadataInfrastructuresResult struct {
	// The list of autonomous_exadata_infrastructures.
	AutonomousExadataInfrastructures []GetAutonomousExadataInfrastructuresAutonomousExadataInfrastructure `pulumi:"autonomousExadataInfrastructures"`
	// The name of the availability domain that the Autonomous Exadata Infrastructure is located in.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The user-friendly name for the Autonomous Exadata Infrastructure.
	DisplayName *string                                     `pulumi:"displayName"`
	Filters     []GetAutonomousExadataInfrastructuresFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current lifecycle state of the Autonomous Exadata Infrastructure.
	State *string `pulumi:"state"`
}
