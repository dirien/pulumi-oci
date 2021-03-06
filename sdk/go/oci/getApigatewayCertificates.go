// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Certificates in Oracle Cloud Infrastructure API Gateway service.
//
// Returns a list of certificates.
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
// 		opt0 := _var.Certificate_display_name
// 		opt1 := _var.Certificate_state
// 		_, err := oci.GetApigatewayCertificates(ctx, &GetApigatewayCertificatesArgs{
// 			CompartmentId: _var.Compartment_id,
// 			DisplayName:   &opt0,
// 			State:         &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetApigatewayCertificates(ctx *pulumi.Context, args *GetApigatewayCertificatesArgs, opts ...pulumi.InvokeOption) (*GetApigatewayCertificatesResult, error) {
	var rv GetApigatewayCertificatesResult
	err := ctx.Invoke("oci:index/getApigatewayCertificates:GetApigatewayCertificates", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetApigatewayCertificates.
type GetApigatewayCertificatesArgs struct {
	// The ocid of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
	DisplayName *string                           `pulumi:"displayName"`
	Filters     []GetApigatewayCertificatesFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state.  Example: `ACTIVE` or `DELETED`
	State *string `pulumi:"state"`
}

// A collection of values returned by GetApigatewayCertificates.
type GetApigatewayCertificatesResult struct {
	// The list of certificate_collection.
	CertificateCollections []GetApigatewayCertificatesCertificateCollection `pulumi:"certificateCollections"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName *string                           `pulumi:"displayName"`
	Filters     []GetApigatewayCertificatesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the certificate.
	State *string `pulumi:"state"`
}
