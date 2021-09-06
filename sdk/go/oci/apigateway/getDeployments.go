// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package apigateway

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Deployments in Oracle Cloud Infrastructure API Gateway service.
//
// Returns a list of deployments.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/apigateway"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Deployment_display_name
// 		opt1 := oci_apigateway_gateway.Test_gateway.Id
// 		opt2 := _var.Deployment_state
// 		_, err := apigateway.GetDeployments(ctx, &apigateway.GetDeploymentsArgs{
// 			CompartmentId: _var.Compartment_id,
// 			DisplayName:   &opt0,
// 			GatewayId:     &opt1,
// 			State:         &opt2,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDeployments(ctx *pulumi.Context, args *GetDeploymentsArgs, opts ...pulumi.InvokeOption) (*GetDeploymentsResult, error) {
	var rv GetDeploymentsResult
	err := ctx.Invoke("oci:apigateway/getDeployments:getDeployments", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDeployments.
type GetDeploymentsArgs struct {
	// The ocid of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
	DisplayName *string                `pulumi:"displayName"`
	Filters     []GetDeploymentsFilter `pulumi:"filters"`
	// Filter deployments by the gateway ocid.
	GatewayId *string `pulumi:"gatewayId"`
	// A filter to return only resources that match the given lifecycle state.  Example: `SUCCEEDED`
	State *string `pulumi:"state"`
}

// A collection of values returned by getDeployments.
type GetDeploymentsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of deployment_collection.
	DeploymentCollections []GetDeploymentsDeploymentCollection `pulumi:"deploymentCollections"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName *string                `pulumi:"displayName"`
	Filters     []GetDeploymentsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
	GatewayId *string `pulumi:"gatewayId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the deployment.
	State *string `pulumi:"state"`
}
