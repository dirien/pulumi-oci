// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Osn resource in Oracle Cloud Infrastructure Blockchain service.
//
// Gets information about an OSN identified by the specific id
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
// 		_, err := oci.GetBlockchainOsn(ctx, &GetBlockchainOsnArgs{
// 			BlockchainPlatformId: oci_blockchain_blockchain_platform.Test_blockchain_platform.Id,
// 			OsnId:                oci_blockchain_osn.Test_osn.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupBlockchainOsn(ctx *pulumi.Context, args *LookupBlockchainOsnArgs, opts ...pulumi.InvokeOption) (*LookupBlockchainOsnResult, error) {
	var rv LookupBlockchainOsnResult
	err := ctx.Invoke("oci:index/getBlockchainOsn:GetBlockchainOsn", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetBlockchainOsn.
type LookupBlockchainOsnArgs struct {
	// Unique service identifier.
	BlockchainPlatformId string `pulumi:"blockchainPlatformId"`
	// OSN identifier.
	OsnId string `pulumi:"osnId"`
}

// A collection of values returned by GetBlockchainOsn.
type LookupBlockchainOsnResult struct {
	// Availability Domain of OSN
	Ad                   string `pulumi:"ad"`
	BlockchainPlatformId string `pulumi:"blockchainPlatformId"`
	Id                   string `pulumi:"id"`
	// OCPU allocation parameter
	OcpuAllocationParam GetBlockchainOsnOcpuAllocationParam `pulumi:"ocpuAllocationParam"`
	OsnId               string                              `pulumi:"osnId"`
	// OSN identifier
	OsnKey string `pulumi:"osnKey"`
	// The current state of the OSN.
	State string `pulumi:"state"`
}
