// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Peer resource in Oracle Cloud Infrastructure Blockchain service.
//
// Create Blockchain Platform Peer
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
// 		_, err := oci.NewBlockchainPeer(ctx, "testPeer", &oci.BlockchainPeerArgs{
// 			Ad:                   pulumi.Any(_var.Peer_ad),
// 			BlockchainPlatformId: pulumi.Any(oci_blockchain_blockchain_platform.Test_blockchain_platform.Id),
// 			OcpuAllocationParam: &BlockchainPeerOcpuAllocationParamArgs{
// 				OcpuAllocationNumber: pulumi.Any(_var.Peer_ocpu_allocation_param_ocpu_allocation_number),
// 			},
// 			Role:  pulumi.Any(_var.Peer_role),
// 			Alias: pulumi.Any(_var.Peer_alias),
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
//
// ## Import
//
// Peers can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/blockchainPeer:BlockchainPeer test_peer "blockchainPlatforms/{blockchainPlatformId}/peers/{peerId}"
// ```
type BlockchainPeer struct {
	pulumi.CustomResourceState

	// Availability Domain to place new peer
	Ad pulumi.StringOutput `pulumi:"ad"`
	// peer alias
	Alias pulumi.StringOutput `pulumi:"alias"`
	// Unique service identifier.
	BlockchainPlatformId pulumi.StringOutput `pulumi:"blockchainPlatformId"`
	// Host on which the Peer exists
	Host pulumi.StringOutput `pulumi:"host"`
	// (Updatable) OCPU allocation parameter
	OcpuAllocationParam BlockchainPeerOcpuAllocationParamOutput `pulumi:"ocpuAllocationParam"`
	// peer identifier
	PeerKey pulumi.StringOutput `pulumi:"peerKey"`
	// Peer role
	Role pulumi.StringOutput `pulumi:"role"`
	// The current state of the peer.
	State pulumi.StringOutput `pulumi:"state"`
}

// NewBlockchainPeer registers a new resource with the given unique name, arguments, and options.
func NewBlockchainPeer(ctx *pulumi.Context,
	name string, args *BlockchainPeerArgs, opts ...pulumi.ResourceOption) (*BlockchainPeer, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Ad == nil {
		return nil, errors.New("invalid value for required argument 'Ad'")
	}
	if args.BlockchainPlatformId == nil {
		return nil, errors.New("invalid value for required argument 'BlockchainPlatformId'")
	}
	if args.OcpuAllocationParam == nil {
		return nil, errors.New("invalid value for required argument 'OcpuAllocationParam'")
	}
	if args.Role == nil {
		return nil, errors.New("invalid value for required argument 'Role'")
	}
	var resource BlockchainPeer
	err := ctx.RegisterResource("oci:index/blockchainPeer:BlockchainPeer", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetBlockchainPeer gets an existing BlockchainPeer resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetBlockchainPeer(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *BlockchainPeerState, opts ...pulumi.ResourceOption) (*BlockchainPeer, error) {
	var resource BlockchainPeer
	err := ctx.ReadResource("oci:index/blockchainPeer:BlockchainPeer", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering BlockchainPeer resources.
type blockchainPeerState struct {
	// Availability Domain to place new peer
	Ad *string `pulumi:"ad"`
	// peer alias
	Alias *string `pulumi:"alias"`
	// Unique service identifier.
	BlockchainPlatformId *string `pulumi:"blockchainPlatformId"`
	// Host on which the Peer exists
	Host *string `pulumi:"host"`
	// (Updatable) OCPU allocation parameter
	OcpuAllocationParam *BlockchainPeerOcpuAllocationParam `pulumi:"ocpuAllocationParam"`
	// peer identifier
	PeerKey *string `pulumi:"peerKey"`
	// Peer role
	Role *string `pulumi:"role"`
	// The current state of the peer.
	State *string `pulumi:"state"`
}

type BlockchainPeerState struct {
	// Availability Domain to place new peer
	Ad pulumi.StringPtrInput
	// peer alias
	Alias pulumi.StringPtrInput
	// Unique service identifier.
	BlockchainPlatformId pulumi.StringPtrInput
	// Host on which the Peer exists
	Host pulumi.StringPtrInput
	// (Updatable) OCPU allocation parameter
	OcpuAllocationParam BlockchainPeerOcpuAllocationParamPtrInput
	// peer identifier
	PeerKey pulumi.StringPtrInput
	// Peer role
	Role pulumi.StringPtrInput
	// The current state of the peer.
	State pulumi.StringPtrInput
}

func (BlockchainPeerState) ElementType() reflect.Type {
	return reflect.TypeOf((*blockchainPeerState)(nil)).Elem()
}

type blockchainPeerArgs struct {
	// Availability Domain to place new peer
	Ad string `pulumi:"ad"`
	// peer alias
	Alias *string `pulumi:"alias"`
	// Unique service identifier.
	BlockchainPlatformId string `pulumi:"blockchainPlatformId"`
	// (Updatable) OCPU allocation parameter
	OcpuAllocationParam BlockchainPeerOcpuAllocationParam `pulumi:"ocpuAllocationParam"`
	// Peer role
	Role string `pulumi:"role"`
}

// The set of arguments for constructing a BlockchainPeer resource.
type BlockchainPeerArgs struct {
	// Availability Domain to place new peer
	Ad pulumi.StringInput
	// peer alias
	Alias pulumi.StringPtrInput
	// Unique service identifier.
	BlockchainPlatformId pulumi.StringInput
	// (Updatable) OCPU allocation parameter
	OcpuAllocationParam BlockchainPeerOcpuAllocationParamInput
	// Peer role
	Role pulumi.StringInput
}

func (BlockchainPeerArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*blockchainPeerArgs)(nil)).Elem()
}

type BlockchainPeerInput interface {
	pulumi.Input

	ToBlockchainPeerOutput() BlockchainPeerOutput
	ToBlockchainPeerOutputWithContext(ctx context.Context) BlockchainPeerOutput
}

func (*BlockchainPeer) ElementType() reflect.Type {
	return reflect.TypeOf((*BlockchainPeer)(nil))
}

func (i *BlockchainPeer) ToBlockchainPeerOutput() BlockchainPeerOutput {
	return i.ToBlockchainPeerOutputWithContext(context.Background())
}

func (i *BlockchainPeer) ToBlockchainPeerOutputWithContext(ctx context.Context) BlockchainPeerOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BlockchainPeerOutput)
}

func (i *BlockchainPeer) ToBlockchainPeerPtrOutput() BlockchainPeerPtrOutput {
	return i.ToBlockchainPeerPtrOutputWithContext(context.Background())
}

func (i *BlockchainPeer) ToBlockchainPeerPtrOutputWithContext(ctx context.Context) BlockchainPeerPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BlockchainPeerPtrOutput)
}

type BlockchainPeerPtrInput interface {
	pulumi.Input

	ToBlockchainPeerPtrOutput() BlockchainPeerPtrOutput
	ToBlockchainPeerPtrOutputWithContext(ctx context.Context) BlockchainPeerPtrOutput
}

type blockchainPeerPtrType BlockchainPeerArgs

func (*blockchainPeerPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**BlockchainPeer)(nil))
}

func (i *blockchainPeerPtrType) ToBlockchainPeerPtrOutput() BlockchainPeerPtrOutput {
	return i.ToBlockchainPeerPtrOutputWithContext(context.Background())
}

func (i *blockchainPeerPtrType) ToBlockchainPeerPtrOutputWithContext(ctx context.Context) BlockchainPeerPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BlockchainPeerPtrOutput)
}

// BlockchainPeerArrayInput is an input type that accepts BlockchainPeerArray and BlockchainPeerArrayOutput values.
// You can construct a concrete instance of `BlockchainPeerArrayInput` via:
//
//          BlockchainPeerArray{ BlockchainPeerArgs{...} }
type BlockchainPeerArrayInput interface {
	pulumi.Input

	ToBlockchainPeerArrayOutput() BlockchainPeerArrayOutput
	ToBlockchainPeerArrayOutputWithContext(context.Context) BlockchainPeerArrayOutput
}

type BlockchainPeerArray []BlockchainPeerInput

func (BlockchainPeerArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*BlockchainPeer)(nil)).Elem()
}

func (i BlockchainPeerArray) ToBlockchainPeerArrayOutput() BlockchainPeerArrayOutput {
	return i.ToBlockchainPeerArrayOutputWithContext(context.Background())
}

func (i BlockchainPeerArray) ToBlockchainPeerArrayOutputWithContext(ctx context.Context) BlockchainPeerArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BlockchainPeerArrayOutput)
}

// BlockchainPeerMapInput is an input type that accepts BlockchainPeerMap and BlockchainPeerMapOutput values.
// You can construct a concrete instance of `BlockchainPeerMapInput` via:
//
//          BlockchainPeerMap{ "key": BlockchainPeerArgs{...} }
type BlockchainPeerMapInput interface {
	pulumi.Input

	ToBlockchainPeerMapOutput() BlockchainPeerMapOutput
	ToBlockchainPeerMapOutputWithContext(context.Context) BlockchainPeerMapOutput
}

type BlockchainPeerMap map[string]BlockchainPeerInput

func (BlockchainPeerMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*BlockchainPeer)(nil)).Elem()
}

func (i BlockchainPeerMap) ToBlockchainPeerMapOutput() BlockchainPeerMapOutput {
	return i.ToBlockchainPeerMapOutputWithContext(context.Background())
}

func (i BlockchainPeerMap) ToBlockchainPeerMapOutputWithContext(ctx context.Context) BlockchainPeerMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BlockchainPeerMapOutput)
}

type BlockchainPeerOutput struct {
	*pulumi.OutputState
}

func (BlockchainPeerOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*BlockchainPeer)(nil))
}

func (o BlockchainPeerOutput) ToBlockchainPeerOutput() BlockchainPeerOutput {
	return o
}

func (o BlockchainPeerOutput) ToBlockchainPeerOutputWithContext(ctx context.Context) BlockchainPeerOutput {
	return o
}

func (o BlockchainPeerOutput) ToBlockchainPeerPtrOutput() BlockchainPeerPtrOutput {
	return o.ToBlockchainPeerPtrOutputWithContext(context.Background())
}

func (o BlockchainPeerOutput) ToBlockchainPeerPtrOutputWithContext(ctx context.Context) BlockchainPeerPtrOutput {
	return o.ApplyT(func(v BlockchainPeer) *BlockchainPeer {
		return &v
	}).(BlockchainPeerPtrOutput)
}

type BlockchainPeerPtrOutput struct {
	*pulumi.OutputState
}

func (BlockchainPeerPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**BlockchainPeer)(nil))
}

func (o BlockchainPeerPtrOutput) ToBlockchainPeerPtrOutput() BlockchainPeerPtrOutput {
	return o
}

func (o BlockchainPeerPtrOutput) ToBlockchainPeerPtrOutputWithContext(ctx context.Context) BlockchainPeerPtrOutput {
	return o
}

type BlockchainPeerArrayOutput struct{ *pulumi.OutputState }

func (BlockchainPeerArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]BlockchainPeer)(nil))
}

func (o BlockchainPeerArrayOutput) ToBlockchainPeerArrayOutput() BlockchainPeerArrayOutput {
	return o
}

func (o BlockchainPeerArrayOutput) ToBlockchainPeerArrayOutputWithContext(ctx context.Context) BlockchainPeerArrayOutput {
	return o
}

func (o BlockchainPeerArrayOutput) Index(i pulumi.IntInput) BlockchainPeerOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) BlockchainPeer {
		return vs[0].([]BlockchainPeer)[vs[1].(int)]
	}).(BlockchainPeerOutput)
}

type BlockchainPeerMapOutput struct{ *pulumi.OutputState }

func (BlockchainPeerMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]BlockchainPeer)(nil))
}

func (o BlockchainPeerMapOutput) ToBlockchainPeerMapOutput() BlockchainPeerMapOutput {
	return o
}

func (o BlockchainPeerMapOutput) ToBlockchainPeerMapOutputWithContext(ctx context.Context) BlockchainPeerMapOutput {
	return o
}

func (o BlockchainPeerMapOutput) MapIndex(k pulumi.StringInput) BlockchainPeerOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) BlockchainPeer {
		return vs[0].(map[string]BlockchainPeer)[vs[1].(string)]
	}).(BlockchainPeerOutput)
}

func init() {
	pulumi.RegisterOutputType(BlockchainPeerOutput{})
	pulumi.RegisterOutputType(BlockchainPeerPtrOutput{})
	pulumi.RegisterOutputType(BlockchainPeerArrayOutput{})
	pulumi.RegisterOutputType(BlockchainPeerMapOutput{})
}
