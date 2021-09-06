// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package artifacts

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Generic Artifacts in Oracle Cloud Infrastructure Artifacts service.
//
// Lists artifacts in the specified repository.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/artifacts"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Generic_artifact_artifact_path
// 		opt1 := _var.Generic_artifact_display_name
// 		opt2 := _var.Generic_artifact_id
// 		opt3 := _var.Generic_artifact_sha256
// 		opt4 := _var.Generic_artifact_state
// 		opt5 := _var.Generic_artifact_version
// 		_, err := artifacts.GetGenericArtifacts(ctx, &artifacts.GetGenericArtifactsArgs{
// 			CompartmentId: _var.Compartment_id,
// 			RepositoryId:  oci_artifacts_repository.Test_repository.Id,
// 			ArtifactPath:  &opt0,
// 			DisplayName:   &opt1,
// 			Id:            &opt2,
// 			Sha256:        &opt3,
// 			State:         &opt4,
// 			Version:       &opt5,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetGenericArtifacts(ctx *pulumi.Context, args *GetGenericArtifactsArgs, opts ...pulumi.InvokeOption) (*GetGenericArtifactsResult, error) {
	var rv GetGenericArtifactsResult
	err := ctx.Invoke("oci:artifacts/getGenericArtifacts:getGenericArtifacts", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getGenericArtifacts.
type GetGenericArtifactsArgs struct {
	// Filter results by a prefix for the `artifactPath` and and return artifacts that begin with the specified prefix in their path.
	ArtifactPath *string `pulumi:"artifactPath"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string                     `pulumi:"displayName"`
	Filters     []GetGenericArtifactsFilter `pulumi:"filters"`
	// A filter to return the resources for the specified OCID.
	Id *string `pulumi:"id"`
	// A filter to return the artifacts only for the specified repository OCID.
	RepositoryId string `pulumi:"repositoryId"`
	// Filter results by a specified SHA256 digest for the artifact.
	Sha256 *string `pulumi:"sha256"`
	// A filter to return only resources that match the given lifecycle state name exactly.
	State *string `pulumi:"state"`
	// Filter results by a prefix for `version` and return artifacts that that begin with the specified prefix in their version.
	Version *string `pulumi:"version"`
}

// A collection of values returned by getGenericArtifacts.
type GetGenericArtifactsResult struct {
	// A user-defined path to describe the location of an artifact. Slashes do not create a directory structure, but you can use slashes to organize the repository. An artifact path does not include an artifact version.  Example: `project01/my-web-app/artifact-abc`
	ArtifactPath *string `pulumi:"artifactPath"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository's compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The artifact name with the format of `<artifact-path>:<artifact-version>`. The artifact name is truncated to a maximum length of 255.  Example: `project01/my-web-app/artifact-abc:1.0.0`
	DisplayName *string                     `pulumi:"displayName"`
	Filters     []GetGenericArtifactsFilter `pulumi:"filters"`
	// The list of generic_artifact_collection.
	GenericArtifactCollections []GetGenericArtifactsGenericArtifactCollection `pulumi:"genericArtifactCollections"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
	Id *string `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.
	RepositoryId string `pulumi:"repositoryId"`
	// The SHA256 digest for the artifact. When you upload an artifact to the repository, a SHA256 digest is calculated and added to the artifact properties.
	Sha256 *string `pulumi:"sha256"`
	// The current state of the artifact.
	State *string `pulumi:"state"`
	// A user-defined string to describe the artifact version.  Example: `1.1.0` or `1.2-beta-2`
	Version *string `pulumi:"version"`
}
