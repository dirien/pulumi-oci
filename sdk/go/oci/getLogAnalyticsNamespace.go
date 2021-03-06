// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Namespace resource in Oracle Cloud Infrastructure Log Analytics service.
//
// This API gets the namespace details of a tenancy already onboarded in Logging Analytics Application
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
// 		_, err := oci.GetLogAnalyticsNamespace(ctx, &GetLogAnalyticsNamespaceArgs{
// 			Namespace: _var.Namespace_namespace,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupLogAnalyticsNamespace(ctx *pulumi.Context, args *LookupLogAnalyticsNamespaceArgs, opts ...pulumi.InvokeOption) (*LookupLogAnalyticsNamespaceResult, error) {
	var rv LookupLogAnalyticsNamespaceResult
	err := ctx.Invoke("oci:index/getLogAnalyticsNamespace:GetLogAnalyticsNamespace", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetLogAnalyticsNamespace.
type LookupLogAnalyticsNamespaceArgs struct {
	// The Logging Analytics namespace used for the request.
	Namespace string `pulumi:"namespace"`
}

// A collection of values returned by GetLogAnalyticsNamespace.
type LookupLogAnalyticsNamespaceResult struct {
	// The is the tenancy ID
	CompartmentId string `pulumi:"compartmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// This indicates if the tenancy is onboarded to Logging Analytics
	IsOnboarded bool `pulumi:"isOnboarded"`
	// This is the namespace name of a tenancy
	Namespace string `pulumi:"namespace"`
}
