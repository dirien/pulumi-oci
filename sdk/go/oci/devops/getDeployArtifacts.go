// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Deploy Artifacts in Oracle Cloud Infrastructure Devops service.
//
// Returns a list of deployment artifacts.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/devops"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Compartment_id
// 		opt1 := _var.Deploy_artifact_display_name
// 		opt2 := _var.Deploy_artifact_id
// 		opt3 := oci_devops_project.Test_project.Id
// 		opt4 := _var.Deploy_artifact_state
// 		_, err := devops.GetDeployArtifacts(ctx, &devops.GetDeployArtifactsArgs{
// 			CompartmentId: &opt0,
// 			DisplayName:   &opt1,
// 			Id:            &opt2,
// 			ProjectId:     &opt3,
// 			State:         &opt4,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDeployArtifacts(ctx *pulumi.Context, args *GetDeployArtifactsArgs, opts ...pulumi.InvokeOption) (*GetDeployArtifactsResult, error) {
	var rv GetDeployArtifactsResult
	err := ctx.Invoke("oci:devops/getDeployArtifacts:getDeployArtifacts", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDeployArtifacts.
type GetDeployArtifactsArgs struct {
	// The OCID of the compartment in which to list resources.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetDeployArtifactsFilter `pulumi:"filters"`
	// Unique identifier or OCID for listing a single resource by ID.
	Id *string `pulumi:"id"`
	// unique project identifier
	ProjectId *string `pulumi:"projectId"`
	// A filter to return only DeployArtifacts that matches the given lifecycleState.
	State *string `pulumi:"state"`
}

// A collection of values returned by getDeployArtifacts.
type GetDeployArtifactsResult struct {
	// The OCID of a compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The list of deploy_artifact_collection.
	DeployArtifactCollections []GetDeployArtifactsDeployArtifactCollection `pulumi:"deployArtifactCollections"`
	// Deployment artifact identifier, which can be renamed and is not necessarily unique. Avoid entering confidential information.
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetDeployArtifactsFilter `pulumi:"filters"`
	// Unique identifier that is immutable on creation.
	Id *string `pulumi:"id"`
	// The OCID of a project.
	ProjectId *string `pulumi:"projectId"`
	// Current state of the deployment artifact.
	State *string `pulumi:"state"`
}
