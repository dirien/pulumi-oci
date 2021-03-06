// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Data Safe Configuration resource in Oracle Cloud Infrastructure Data Safe service.
//
// Gets the details of the Data Safe configuration.
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
// 		_, err := oci.GetDataSafeDataSafeConfiguration(ctx, &GetDataSafeDataSafeConfigurationArgs{
// 			CompartmentId: _var.Compartment_id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupDataSafeDataSafeConfiguration(ctx *pulumi.Context, args *LookupDataSafeDataSafeConfigurationArgs, opts ...pulumi.InvokeOption) (*LookupDataSafeDataSafeConfigurationResult, error) {
	var rv LookupDataSafeDataSafeConfigurationResult
	err := ctx.Invoke("oci:index/getDataSafeDataSafeConfiguration:GetDataSafeDataSafeConfiguration", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetDataSafeDataSafeConfiguration.
type LookupDataSafeDataSafeConfigurationArgs struct {
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
}

// A collection of values returned by GetDataSafeDataSafeConfiguration.
type LookupDataSafeDataSafeConfigurationResult struct {
	// The OCID of the tenancy used to enable Data Safe.
	CompartmentId string `pulumi:"compartmentId"`
	Id            string `pulumi:"id"`
	// Indicates if Data Safe is enabled.
	IsEnabled bool `pulumi:"isEnabled"`
	// The current state of Data Safe.
	State string `pulumi:"state"`
	// The date and time Data Safe was enabled, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeEnabled string `pulumi:"timeEnabled"`
	// The URL of the Data Safe service.
	Url string `pulumi:"url"`
}
