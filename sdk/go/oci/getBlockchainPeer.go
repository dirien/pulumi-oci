// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Peer resource in Oracle Cloud Infrastructure Blockchain service.
//
// Gets information about a peer identified by the specific id
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
// 		_, err := oci.GetBlockchainPeer(ctx, &GetBlockchainPeerArgs{
// 			BlockchainPlatformId: oci_blockchain_blockchain_platform.Test_blockchain_platform.Id,
// 			PeerId:               oci_blockchain_peer.Test_peer.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupBlockchainPeer(ctx *pulumi.Context, args *LookupBlockchainPeerArgs, opts ...pulumi.InvokeOption) (*LookupBlockchainPeerResult, error) {
	var rv LookupBlockchainPeerResult
	err := ctx.Invoke("oci:index/getBlockchainPeer:GetBlockchainPeer", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetBlockchainPeer.
type LookupBlockchainPeerArgs struct {
	// Unique service identifier.
	BlockchainPlatformId string `pulumi:"blockchainPlatformId"`
	// Peer identifier.
	PeerId string `pulumi:"peerId"`
}

// A collection of values returned by GetBlockchainPeer.
type LookupBlockchainPeerResult struct {
	// Availability Domain of peer
	Ad string `pulumi:"ad"`
	// peer alias
	Alias                string `pulumi:"alias"`
	BlockchainPlatformId string `pulumi:"blockchainPlatformId"`
	// Host on which the Peer exists
	Host string `pulumi:"host"`
	Id   string `pulumi:"id"`
	// OCPU allocation parameter
	OcpuAllocationParam GetBlockchainPeerOcpuAllocationParam `pulumi:"ocpuAllocationParam"`
	PeerId              string                               `pulumi:"peerId"`
	// peer identifier
	PeerKey string `pulumi:"peerKey"`
	// Peer role
	Role string `pulumi:"role"`
	// The current state of the peer.
	State string `pulumi:"state"`
}
