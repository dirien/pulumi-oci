// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Peers in Oracle Cloud Infrastructure Blockchain service.
//
// List Blockchain Platform Peers
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
// 		opt0 := _var.Peer_display_name
// 		_, err := oci.GetBlockchainPeers(ctx, &GetBlockchainPeersArgs{
// 			BlockchainPlatformId: oci_blockchain_blockchain_platform.Test_blockchain_platform.Id,
// 			DisplayName:          &opt0,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetBlockchainPeers(ctx *pulumi.Context, args *GetBlockchainPeersArgs, opts ...pulumi.InvokeOption) (*GetBlockchainPeersResult, error) {
	var rv GetBlockchainPeersResult
	err := ctx.Invoke("oci:index/getBlockchainPeers:GetBlockchainPeers", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetBlockchainPeers.
type GetBlockchainPeersArgs struct {
	// Unique service identifier.
	BlockchainPlatformId string `pulumi:"blockchainPlatformId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Example: `My new resource`
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetBlockchainPeersFilter `pulumi:"filters"`
}

// A collection of values returned by GetBlockchainPeers.
type GetBlockchainPeersResult struct {
	BlockchainPlatformId string                     `pulumi:"blockchainPlatformId"`
	DisplayName          *string                    `pulumi:"displayName"`
	Filters              []GetBlockchainPeersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of peer_collection.
	PeerCollections []GetBlockchainPeersPeerCollection `pulumi:"peerCollections"`
}
