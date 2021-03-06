// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Api Validation resource in Oracle Cloud Infrastructure API Gateway service.
//
// Gets the API validation results.
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
// 		_, err := oci.GetApigatewayApiValidation(ctx, &GetApigatewayApiValidationArgs{
// 			ApiId: oci_apigateway_api.Test_api.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetApigatewayApiValidation(ctx *pulumi.Context, args *GetApigatewayApiValidationArgs, opts ...pulumi.InvokeOption) (*GetApigatewayApiValidationResult, error) {
	var rv GetApigatewayApiValidationResult
	err := ctx.Invoke("oci:index/getApigatewayApiValidation:GetApigatewayApiValidation", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetApigatewayApiValidation.
type GetApigatewayApiValidationArgs struct {
	// The ocid of the API.
	ApiId string `pulumi:"apiId"`
}

// A collection of values returned by GetApigatewayApiValidation.
type GetApigatewayApiValidationResult struct {
	ApiId string `pulumi:"apiId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// API validation results.
	Validations []GetApigatewayApiValidationValidation `pulumi:"validations"`
}
