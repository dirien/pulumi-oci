// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package artifacts

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
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/artifacts"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := artifacts.LookupContainerConfiguration(ctx, &artifacts.LookupContainerConfigurationArgs{
// 			CompartmentId: _var.Compartment_id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupContainerConfiguration(ctx *pulumi.Context, args *LookupContainerConfigurationArgs, opts ...pulumi.InvokeOption) (*LookupContainerConfigurationResult, error) {
	var rv LookupContainerConfigurationResult
	err := ctx.Invoke("oci:artifacts/getContainerConfiguration:getContainerConfiguration", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getContainerConfiguration.
type LookupContainerConfigurationArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
}

// A collection of values returned by getContainerConfiguration.
type LookupContainerConfigurationResult struct {
	CompartmentId string `pulumi:"compartmentId"`
	Id            string `pulumi:"id"`
	// Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
	IsRepositoryCreatedOnFirstPush bool `pulumi:"isRepositoryCreatedOnFirstPush"`
	// The tenancy namespace used in the container repository path.
	Namespace string `pulumi:"namespace"`
}
