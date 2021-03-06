// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Profiles in Oracle Cloud Infrastructure Optimizer service.
//
// Lists the existing profiles.
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
// 		opt0 := _var.Profile_name
// 		opt1 := _var.Profile_state
// 		_, err := oci.GetOptimizerProfiles(ctx, &GetOptimizerProfilesArgs{
// 			CompartmentId: _var.Compartment_id,
// 			Name:          &opt0,
// 			State:         &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetOptimizerProfiles(ctx *pulumi.Context, args *GetOptimizerProfilesArgs, opts ...pulumi.InvokeOption) (*GetOptimizerProfilesResult, error) {
	var rv GetOptimizerProfilesResult
	err := ctx.Invoke("oci:index/getOptimizerProfiles:GetOptimizerProfiles", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetOptimizerProfiles.
type GetOptimizerProfilesArgs struct {
	// The OCID of the compartment.
	CompartmentId string                       `pulumi:"compartmentId"`
	Filters       []GetOptimizerProfilesFilter `pulumi:"filters"`
	// Optional. A filter that returns results that match the name specified.
	Name *string `pulumi:"name"`
	// A filter that returns results that match the lifecycle state specified.
	State *string `pulumi:"state"`
}

// A collection of values returned by GetOptimizerProfiles.
type GetOptimizerProfilesResult struct {
	// The OCID of the tenancy. The tenancy is the root compartment.
	CompartmentId string                       `pulumi:"compartmentId"`
	Filters       []GetOptimizerProfilesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The name assigned to the profile. Avoid entering confidential information.
	Name *string `pulumi:"name"`
	// The list of profile_collection.
	ProfileCollections []GetOptimizerProfilesProfileCollection `pulumi:"profileCollections"`
	// The profile's current state.
	State *string `pulumi:"state"`
}
