// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Cloud Exadata Infrastructures in Oracle Cloud Infrastructure Database service.
//
// Gets a list of the cloud Exadata infrastructure resources in the specified compartment. Applies to Exadata Cloud Service instances only.
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
// 		opt0 := _var.Cloud_exadata_infrastructure_display_name
// 		opt1 := _var.Cloud_exadata_infrastructure_state
// 		_, err := oci.GetDatabaseCloudExadataInfrastructures(ctx, &GetDatabaseCloudExadataInfrastructuresArgs{
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
func GetDatabaseCloudExadataInfrastructures(ctx *pulumi.Context, args *GetDatabaseCloudExadataInfrastructuresArgs, opts ...pulumi.InvokeOption) (*GetDatabaseCloudExadataInfrastructuresResult, error) {
	var rv GetDatabaseCloudExadataInfrastructuresResult
	err := ctx.Invoke("oci:index/getDatabaseCloudExadataInfrastructures:GetDatabaseCloudExadataInfrastructures", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetDatabaseCloudExadataInfrastructures.
type GetDatabaseCloudExadataInfrastructuresArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string                                        `pulumi:"displayName"`
	Filters     []GetDatabaseCloudExadataInfrastructuresFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
}

// A collection of values returned by GetDatabaseCloudExadataInfrastructures.
type GetDatabaseCloudExadataInfrastructuresResult struct {
	// The list of cloud_exadata_infrastructures.
	CloudExadataInfrastructures []GetDatabaseCloudExadataInfrastructuresCloudExadataInfrastructure `pulumi:"cloudExadataInfrastructures"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The user-friendly name for the cloud Exadata infrastructure resource. The name does not need to be unique.
	DisplayName *string                                        `pulumi:"displayName"`
	Filters     []GetDatabaseCloudExadataInfrastructuresFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current lifecycle state of the cloud Exadata infrastructure resource.
	State *string `pulumi:"state"`
}
