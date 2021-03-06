// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Data Keys in Oracle Cloud Infrastructure Apm service.
//
// Lists all Data Keys for the specified APM Domain. The caller may filter the list by specifying the 'dataKeyType'
// query parameter.
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
// 		opt0 := _var.Data_key_data_key_type
// 		_, err := oci.GetApmDataKeys(ctx, &GetApmDataKeysArgs{
// 			ApmDomainId: oci_apm_apm_domain.Test_apm_domain.Id,
// 			DataKeyType: &opt0,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetApmDataKeys(ctx *pulumi.Context, args *GetApmDataKeysArgs, opts ...pulumi.InvokeOption) (*GetApmDataKeysResult, error) {
	var rv GetApmDataKeysResult
	err := ctx.Invoke("oci:index/getApmDataKeys:GetApmDataKeys", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetApmDataKeys.
type GetApmDataKeysArgs struct {
	// OCID of the APM Domain
	ApmDomainId string `pulumi:"apmDomainId"`
	// Data key type.
	DataKeyType *string                `pulumi:"dataKeyType"`
	Filters     []GetApmDataKeysFilter `pulumi:"filters"`
}

// A collection of values returned by GetApmDataKeys.
type GetApmDataKeysResult struct {
	ApmDomainId string  `pulumi:"apmDomainId"`
	DataKeyType *string `pulumi:"dataKeyType"`
	// The list of data_keys.
	DataKeys []GetApmDataKeysDataKey `pulumi:"dataKeys"`
	Filters  []GetApmDataKeysFilter  `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}
