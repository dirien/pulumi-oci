// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package cloudguard

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Detector Recipes in Oracle Cloud Infrastructure Cloud Guard service.
//
// Returns a list of all Detector Recipes in a compartment
//
// The ListDetectorRecipes operation returns only the detector recipes in `compartmentId` passed.
// The list does not include any subcompartments of the compartmentId passed.
//
// The parameter `accessLevel` specifies whether to return only those compartments for which the
// requestor has INSPECT permissions on at least one resource directly
// or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
// Principal doesn't have access to even one of the child compartments. This is valid only when
// `compartmentIdInSubtree` is set to `true`.
//
// The parameter `compartmentIdInSubtree` applies when you perform ListDetectorRecipes on the
// `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
// To get a full list of all compartments and subcompartments in the tenancy (root compartment),
// set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/cloudguard"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Detector_recipe_access_level
// 		opt1 := _var.Detector_recipe_compartment_id_in_subtree
// 		opt2 := _var.Detector_recipe_display_name
// 		opt3 := _var.Detector_recipe_resource_metadata_only
// 		opt4 := _var.Detector_recipe_state
// 		_, err := cloudguard.GetDetectorRecipes(ctx, &cloudguard.GetDetectorRecipesArgs{
// 			CompartmentId:          _var.Compartment_id,
// 			AccessLevel:            &opt0,
// 			CompartmentIdInSubtree: &opt1,
// 			DisplayName:            &opt2,
// 			ResourceMetadataOnly:   &opt3,
// 			State:                  &opt4,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDetectorRecipes(ctx *pulumi.Context, args *GetDetectorRecipesArgs, opts ...pulumi.InvokeOption) (*GetDetectorRecipesResult, error) {
	var rv GetDetectorRecipesResult
	err := ctx.Invoke("oci:cloudguard/getDetectorRecipes:getDetectorRecipes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDetectorRecipes.
type GetDetectorRecipesArgs struct {
	// Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
	AccessLevel *string `pulumi:"accessLevel"`
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
	CompartmentIdInSubtree *bool `pulumi:"compartmentIdInSubtree"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetDetectorRecipesFilter `pulumi:"filters"`
	// Default is false. When set to true, the list of all Oracle Managed Resources Metadata supported by Cloud Guard are returned.
	ResourceMetadataOnly *bool `pulumi:"resourceMetadataOnly"`
	// The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
	State *string `pulumi:"state"`
}

// A collection of values returned by getDetectorRecipes.
type GetDetectorRecipesResult struct {
	AccessLevel *string `pulumi:"accessLevel"`
	// compartmentId of detector recipe
	CompartmentId          string `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool  `pulumi:"compartmentIdInSubtree"`
	// The list of detector_recipe_collection.
	DetectorRecipeCollections []GetDetectorRecipesDetectorRecipeCollection `pulumi:"detectorRecipeCollections"`
	// displayName
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetDetectorRecipesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                   string `pulumi:"id"`
	ResourceMetadataOnly *bool  `pulumi:"resourceMetadataOnly"`
	// The current state of the resource.
	State *string `pulumi:"state"`
}
