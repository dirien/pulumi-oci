// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Container Configuration resource in Oracle Cloud Infrastructure Artifacts service.
//
// Get container configuration.
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
// 		_, err := oci.GetArtifactsContainerConfiguration(ctx, &GetArtifactsContainerConfigurationArgs{
// 			CompartmentId: _var.Compartment_id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupArtifactsContainerConfiguration(ctx *pulumi.Context, args *LookupArtifactsContainerConfigurationArgs, opts ...pulumi.InvokeOption) (*LookupArtifactsContainerConfigurationResult, error) {
	var rv LookupArtifactsContainerConfigurationResult
	err := ctx.Invoke("oci:index/getArtifactsContainerConfiguration:GetArtifactsContainerConfiguration", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetArtifactsContainerConfiguration.
type LookupArtifactsContainerConfigurationArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
}

// A collection of values returned by GetArtifactsContainerConfiguration.
type LookupArtifactsContainerConfigurationResult struct {
	CompartmentId string `pulumi:"compartmentId"`
	Id            string `pulumi:"id"`
	// Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
	IsRepositoryCreatedOnFirstPush bool `pulumi:"isRepositoryCreatedOnFirstPush"`
	// The tenancy namespace used in the container repository path.
	Namespace string `pulumi:"namespace"`
}
