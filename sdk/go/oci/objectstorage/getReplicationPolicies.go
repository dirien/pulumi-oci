// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package objectstorage

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
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/objectstorage"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := objectstorage.GetReplicationPolicies(ctx, &objectstorage.GetReplicationPoliciesArgs{
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
func GetReplicationPolicies(ctx *pulumi.Context, args *GetReplicationPoliciesArgs, opts ...pulumi.InvokeOption) (*GetReplicationPoliciesResult, error) {
	var rv GetReplicationPoliciesResult
	err := ctx.Invoke("oci:objectstorage/getReplicationPolicies:getReplicationPolicies", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getReplicationPolicies.
type GetReplicationPoliciesArgs struct {
	// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
	Bucket  string                         `pulumi:"bucket"`
	Filters []GetReplicationPoliciesFilter `pulumi:"filters"`
	// The Object Storage namespace used for the request.
	Namespace string `pulumi:"namespace"`
}

// A collection of values returned by getReplicationPolicies.
type GetReplicationPoliciesResult struct {
	Bucket  string                         `pulumi:"bucket"`
	Filters []GetReplicationPoliciesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id        string `pulumi:"id"`
	Namespace string `pulumi:"namespace"`
	// The list of replication_policies.
	ReplicationPolicies []GetReplicationPoliciesReplicationPolicy `pulumi:"replicationPolicies"`
}
