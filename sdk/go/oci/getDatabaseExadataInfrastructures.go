// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Exadata Infrastructures in Oracle Cloud Infrastructure Database service.
//
// Lists the Exadata infrastructure resources in the specified compartment. Applies to Exadata Cloud@Customer instances only.
// To list the Exadata Cloud Service infrastructure resources in a compartment, use the  [ListCloudExadataInfrastructures](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudExadataInfrastructure/ListCloudExadataInfrastructures) operation.
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
// 		opt0 := _var.Exadata_infrastructure_display_name
// 		opt1 := _var.Exadata_infrastructure_state
// 		_, err := oci.GetDatabaseExadataInfrastructures(ctx, &GetDatabaseExadataInfrastructuresArgs{
// 			CompartmentId: _var.Compartment_id,
// 			DisplayName:   &opt0,
// 			State:         &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDatabaseExadataInfrastructures(ctx *pulumi.Context, args *GetDatabaseExadataInfrastructuresArgs, opts ...pulumi.InvokeOption) (*GetDatabaseExadataInfrastructuresResult, error) {
	var rv GetDatabaseExadataInfrastructuresResult
	err := ctx.Invoke("oci:index/getDatabaseExadataInfrastructures:GetDatabaseExadataInfrastructures", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetDatabaseExadataInfrastructures.
type GetDatabaseExadataInfrastructuresArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string                                   `pulumi:"displayName"`
	Filters     []GetDatabaseExadataInfrastructuresFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
}

// A collection of values returned by GetDatabaseExadataInfrastructures.
type GetDatabaseExadataInfrastructuresResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The user-friendly name for the Exadata Cloud@Customer infrastructure. The name does not need to be unique.
	DisplayName *string `pulumi:"displayName"`
	// The list of exadata_infrastructures.
	ExadataInfrastructures []GetDatabaseExadataInfrastructuresExadataInfrastructure `pulumi:"exadataInfrastructures"`
	Filters                []GetDatabaseExadataInfrastructuresFilter                `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current lifecycle state of the Exadata infrastructure.
	State *string `pulumi:"state"`
}