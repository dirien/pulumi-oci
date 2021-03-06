// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Repositories in Oracle Cloud Infrastructure Artifacts service.
//
// Lists repositories in the specified compartment.
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
// 		opt0 := _var.Repository_display_name
// 		opt1 := _var.Repository_id
// 		opt2 := _var.Repository_is_immutable
// 		opt3 := _var.Repository_state
// 		_, err := oci.GetArtifactsRepositories(ctx, &GetArtifactsRepositoriesArgs{
// 			CompartmentId: _var.Compartment_id,
// 			DisplayName:   &opt0,
// 			Id:            &opt1,
// 			IsImmutable:   &opt2,
// 			State:         &opt3,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetArtifactsRepositories(ctx *pulumi.Context, args *GetArtifactsRepositoriesArgs, opts ...pulumi.InvokeOption) (*GetArtifactsRepositoriesResult, error) {
	var rv GetArtifactsRepositoriesResult
	err := ctx.Invoke("oci:index/getArtifactsRepositories:GetArtifactsRepositories", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetArtifactsRepositories.
type GetArtifactsRepositoriesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string                          `pulumi:"displayName"`
	Filters     []GetArtifactsRepositoriesFilter `pulumi:"filters"`
	// A filter to return the resources for the specified OCID.
	Id *string `pulumi:"id"`
	// A filter to return resources that match the isImmutable value.
	IsImmutable *bool `pulumi:"isImmutable"`
	// A filter to return only resources that match the given lifecycle state name exactly.
	State *string `pulumi:"state"`
}

// A collection of values returned by GetArtifactsRepositories.
type GetArtifactsRepositoriesResult struct {
	// The OCID of the repository's compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The repository name.
	DisplayName *string                          `pulumi:"displayName"`
	Filters     []GetArtifactsRepositoriesFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.  Example: `ocid1.artifactrepository.oc1..exampleuniqueID`
	Id *string `pulumi:"id"`
	// Whether the repository is immutable. The artifacts of an immutable repository cannot be overwritten.
	IsImmutable *bool `pulumi:"isImmutable"`
	// The list of repository_collection.
	RepositoryCollections []GetArtifactsRepositoriesRepositoryCollection `pulumi:"repositoryCollections"`
	// The current state of the repository.
	State *string `pulumi:"state"`
}
