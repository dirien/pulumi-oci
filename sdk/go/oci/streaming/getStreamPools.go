// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package streaming

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Stream Pools in Oracle Cloud Infrastructure Streaming service.
//
// List the stream pools for a given compartment ID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/streaming"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Stream_pool_id
// 		opt1 := _var.Stream_pool_name
// 		opt2 := _var.Stream_pool_state
// 		_, err := streaming.GetStreamPools(ctx, &streaming.GetStreamPoolsArgs{
// 			CompartmentId: _var.Compartment_id,
// 			Id:            &opt0,
// 			Name:          &opt1,
// 			State:         &opt2,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetStreamPools(ctx *pulumi.Context, args *GetStreamPoolsArgs, opts ...pulumi.InvokeOption) (*GetStreamPoolsResult, error) {
	var rv GetStreamPoolsResult
	err := ctx.Invoke("oci:streaming/getStreamPools:getStreamPools", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getStreamPools.
type GetStreamPoolsArgs struct {
	// The OCID of the compartment.
	CompartmentId string                 `pulumi:"compartmentId"`
	Filters       []GetStreamPoolsFilter `pulumi:"filters"`
	// A filter to return only resources that match the given ID exactly.
	Id *string `pulumi:"id"`
	// A filter to return only resources that match the given name exactly.
	Name *string `pulumi:"name"`
	// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getStreamPools.
type GetStreamPoolsResult struct {
	// Compartment OCID that the pool belongs to.
	CompartmentId string                 `pulumi:"compartmentId"`
	Filters       []GetStreamPoolsFilter `pulumi:"filters"`
	// The OCID of the stream pool.
	Id *string `pulumi:"id"`
	// The name of the stream pool.
	Name *string `pulumi:"name"`
	// The current state of the stream pool.
	State *string `pulumi:"state"`
	// The list of stream_pools.
	StreamPools []GetStreamPoolsStreamPool `pulumi:"streamPools"`
}
