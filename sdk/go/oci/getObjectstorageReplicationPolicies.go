// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Replication Policies in Oracle Cloud Infrastructure Object Storage service.
//
// List the replication policies associated with a bucket.
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
// 		_, err := oci.GetObjectstorageReplicationPolicies(ctx, &GetObjectstorageReplicationPoliciesArgs{
// 			Bucket:    _var.Replication_policy_bucket,
// 			Namespace: _var.Replication_policy_namespace,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetObjectstorageReplicationPolicies(ctx *pulumi.Context, args *GetObjectstorageReplicationPoliciesArgs, opts ...pulumi.InvokeOption) (*GetObjectstorageReplicationPoliciesResult, error) {
	var rv GetObjectstorageReplicationPoliciesResult
	err := ctx.Invoke("oci:index/getObjectstorageReplicationPolicies:GetObjectstorageReplicationPolicies", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetObjectstorageReplicationPolicies.
type GetObjectstorageReplicationPoliciesArgs struct {
	// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
	Bucket  string                                      `pulumi:"bucket"`
	Filters []GetObjectstorageReplicationPoliciesFilter `pulumi:"filters"`
	// The Object Storage namespace used for the request.
	Namespace string `pulumi:"namespace"`
}

// A collection of values returned by GetObjectstorageReplicationPolicies.
type GetObjectstorageReplicationPoliciesResult struct {
	Bucket  string                                      `pulumi:"bucket"`
	Filters []GetObjectstorageReplicationPoliciesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id        string `pulumi:"id"`
	Namespace string `pulumi:"namespace"`
	// The list of replication_policies.
	ReplicationPolicies []GetObjectstorageReplicationPoliciesReplicationPolicy `pulumi:"replicationPolicies"`
}
