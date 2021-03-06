// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Replication Status resource in Oracle Cloud Infrastructure Kms service.
//
// When a vault has a replica, each operation on the vault or its resources, such as
// keys, is replicated and has an associated replicationId. Replication status provides
// details about whether the operation associated with the given replicationId has been
// successfully applied across replicas.
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
// 		_, err := oci.GetKmsReplicationStatus(ctx, &GetKmsReplicationStatusArgs{
// 			ReplicationId:      oci_kms_replication.Test_replication.Id,
// 			ManagementEndpoint: _var.Replication_status_management_endpoint,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetKmsReplicationStatus(ctx *pulumi.Context, args *GetKmsReplicationStatusArgs, opts ...pulumi.InvokeOption) (*GetKmsReplicationStatusResult, error) {
	var rv GetKmsReplicationStatusResult
	err := ctx.Invoke("oci:index/getKmsReplicationStatus:GetKmsReplicationStatus", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetKmsReplicationStatus.
type GetKmsReplicationStatusArgs struct {
	// The service endpoint to perform management operations against. See Vault Management endpoint.
	ManagementEndpoint string `pulumi:"managementEndpoint"`
	// replicationId associated with an operation on a resource
	ReplicationId string `pulumi:"replicationId"`
}

// A collection of values returned by GetKmsReplicationStatus.
type GetKmsReplicationStatusResult struct {
	// The provider-assigned unique ID for this managed resource.
	Id                 string                                 `pulumi:"id"`
	ManagementEndpoint string                                 `pulumi:"managementEndpoint"`
	ReplicaDetails     []GetKmsReplicationStatusReplicaDetail `pulumi:"replicaDetails"`
	ReplicationId      string                                 `pulumi:"replicationId"`
}
