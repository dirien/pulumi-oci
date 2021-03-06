// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Supported Vmware Software Versions in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
//
// Lists the versions of bundled VMware software supported by the Oracle Cloud
// VMware Solution.
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
// 		_, err := oci.GetOcvpSupportedVmwareSoftwareVersions(ctx, &GetOcvpSupportedVmwareSoftwareVersionsArgs{
// 			CompartmentId: _var.Compartment_id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetOcvpSupportedVmwareSoftwareVersions(ctx *pulumi.Context, args *GetOcvpSupportedVmwareSoftwareVersionsArgs, opts ...pulumi.InvokeOption) (*GetOcvpSupportedVmwareSoftwareVersionsResult, error) {
	var rv GetOcvpSupportedVmwareSoftwareVersionsResult
	err := ctx.Invoke("oci:index/getOcvpSupportedVmwareSoftwareVersions:GetOcvpSupportedVmwareSoftwareVersions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetOcvpSupportedVmwareSoftwareVersions.
type GetOcvpSupportedVmwareSoftwareVersionsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                                         `pulumi:"compartmentId"`
	Filters       []GetOcvpSupportedVmwareSoftwareVersionsFilter `pulumi:"filters"`
}

// A collection of values returned by GetOcvpSupportedVmwareSoftwareVersions.
type GetOcvpSupportedVmwareSoftwareVersionsResult struct {
	CompartmentId string                                         `pulumi:"compartmentId"`
	Filters       []GetOcvpSupportedVmwareSoftwareVersionsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// A list of the supported versions of bundled VMware software.
	Items []GetOcvpSupportedVmwareSoftwareVersionsItem `pulumi:"items"`
}
