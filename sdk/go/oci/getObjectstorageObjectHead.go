// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about metadata of a specific Object resource in Oracle Cloud Infrastructure Object Storage service.
//
// Gets the metadata of an object.
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
// 		_, err := oci.GetObjectstorageObjectHead(ctx, &GetObjectstorageObjectHeadArgs{
// 			Bucket:    _var.Object_bucket,
// 			Namespace: _var.Object_namespace,
// 			Object:    _var.Object_object,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetObjectstorageObjectHead(ctx *pulumi.Context, args *GetObjectstorageObjectHeadArgs, opts ...pulumi.InvokeOption) (*GetObjectstorageObjectHeadResult, error) {
	var rv GetObjectstorageObjectHeadResult
	err := ctx.Invoke("oci:index/getObjectstorageObjectHead:GetObjectstorageObjectHead", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetObjectstorageObjectHead.
type GetObjectstorageObjectHeadArgs struct {
	// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
	Bucket string `pulumi:"bucket"`
	// The top-level namespace used for the request.
	Namespace string `pulumi:"namespace"`
	// The name of the object. Avoid entering confidential information. Example: `test/object1.log`
	Object string `pulumi:"object"`
}

// A collection of values returned by GetObjectstorageObjectHead.
type GetObjectstorageObjectHeadResult struct {
	ArchivalState string `pulumi:"archivalState"`
	Bucket        string `pulumi:"bucket"`
	// The content-length of the object
	ContentLength int `pulumi:"contentLength"`
	// The content-type of the object
	ContentType string `pulumi:"contentType"`
	// The etag of the object
	Etag string `pulumi:"etag"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The metadata of the object
	Metadata  map[string]interface{} `pulumi:"metadata"`
	Namespace string                 `pulumi:"namespace"`
	Object    string                 `pulumi:"object"`
	// The storage tier that the object is stored in.
	// * `archival-state` - Archival state of an object. This field is set only for objects in Archive tier.
	StorageTier string `pulumi:"storageTier"`
}