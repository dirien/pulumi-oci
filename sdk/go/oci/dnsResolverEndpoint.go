// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Resolver Endpoint resource in Oracle Cloud Infrastructure DNS service.
//
// Creates a new resolver endpoint. Requires a `PRIVATE` scope query parameter.
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
// 		_, err := oci.NewDnsResolverEndpoint(ctx, "testResolverEndpoint", &oci.DnsResolverEndpointArgs{
// 			IsForwarding:      pulumi.Any(_var.Resolver_endpoint_is_forwarding),
// 			IsListening:       pulumi.Any(_var.Resolver_endpoint_is_listening),
// 			ResolverId:        pulumi.Any(oci_dns_resolver.Test_resolver.Id),
// 			SubnetId:          pulumi.Any(oci_core_subnet.Test_subnet.Id),
// 			Scope:             pulumi.String("PRIVATE"),
// 			EndpointType:      pulumi.Any(_var.Resolver_endpoint_endpoint_type),
// 			ForwardingAddress: pulumi.Any(_var.Resolver_endpoint_forwarding_address),
// 			ListeningAddress:  pulumi.Any(_var.Resolver_endpoint_listening_address),
// 			NsgIds:            pulumi.Any(_var.Resolver_endpoint_nsg_ids),
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
// For legacy ResolverEndpoints created without `scope`, these ResolverEndpoints can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/dnsResolverEndpoint:DnsResolverEndpoint test_resolver_endpoint "resolverId/{resolverId}/name/{resolverEndpointName}"
// ```
//
//  For ResolverEndpoints created using `scope`, these ResolverEndpoints can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/dnsResolverEndpoint:DnsResolverEndpoint test_resolver_endpoint "resolverId/{resolverId}/name/{name}/scope/{scope}"
// ```
type DnsResolverEndpoint struct {
	pulumi.CustomResourceState

	// The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver's compartment is changed.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
	EndpointType pulumi.StringOutput `pulumi:"endpointType"`
	// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
	ForwardingAddress pulumi.StringOutput `pulumi:"forwardingAddress"`
	// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
	IsForwarding pulumi.BoolOutput `pulumi:"isForwarding"`
	// A Boolean flag indicating whether or not the resolver endpoint is for listening.
	IsListening pulumi.BoolOutput `pulumi:"isListening"`
	// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
	ListeningAddress pulumi.StringOutput `pulumi:"listeningAddress"`
	// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
	Name pulumi.StringOutput `pulumi:"name"`
	// An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
	NsgIds pulumi.StringArrayOutput `pulumi:"nsgIds"`
	// The OCID of the target resolver.
	ResolverId pulumi.StringOutput `pulumi:"resolverId"`
	// Value must be `PRIVATE` when creating private name resolver endpoints.
	Scope pulumi.StringOutput `pulumi:"scope"`
	// The canonical absolute URL of the resource.
	Self pulumi.StringOutput `pulumi:"self"`
	// The current state of the resource.
	State pulumi.StringOutput `pulumi:"state"`
	// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
	SubnetId pulumi.StringOutput `pulumi:"subnetId"`
	// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewDnsResolverEndpoint registers a new resource with the given unique name, arguments, and options.
func NewDnsResolverEndpoint(ctx *pulumi.Context,
	name string, args *DnsResolverEndpointArgs, opts ...pulumi.ResourceOption) (*DnsResolverEndpoint, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.IsForwarding == nil {
		return nil, errors.New("invalid value for required argument 'IsForwarding'")
	}
	if args.IsListening == nil {
		return nil, errors.New("invalid value for required argument 'IsListening'")
	}
	if args.ResolverId == nil {
		return nil, errors.New("invalid value for required argument 'ResolverId'")
	}
	if args.Scope == nil {
		return nil, errors.New("invalid value for required argument 'Scope'")
	}
	if args.SubnetId == nil {
		return nil, errors.New("invalid value for required argument 'SubnetId'")
	}
	var resource DnsResolverEndpoint
	err := ctx.RegisterResource("oci:index/dnsResolverEndpoint:DnsResolverEndpoint", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDnsResolverEndpoint gets an existing DnsResolverEndpoint resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDnsResolverEndpoint(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DnsResolverEndpointState, opts ...pulumi.ResourceOption) (*DnsResolverEndpoint, error) {
	var resource DnsResolverEndpoint
	err := ctx.ReadResource("oci:index/dnsResolverEndpoint:DnsResolverEndpoint", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DnsResolverEndpoint resources.
type dnsResolverEndpointState struct {
	// The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver's compartment is changed.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
	EndpointType *string `pulumi:"endpointType"`
	// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
	ForwardingAddress *string `pulumi:"forwardingAddress"`
	// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
	IsForwarding *bool `pulumi:"isForwarding"`
	// A Boolean flag indicating whether or not the resolver endpoint is for listening.
	IsListening *bool `pulumi:"isListening"`
	// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
	ListeningAddress *string `pulumi:"listeningAddress"`
	// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
	Name *string `pulumi:"name"`
	// An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
	NsgIds []string `pulumi:"nsgIds"`
	// The OCID of the target resolver.
	ResolverId *string `pulumi:"resolverId"`
	// Value must be `PRIVATE` when creating private name resolver endpoints.
	Scope *string `pulumi:"scope"`
	// The canonical absolute URL of the resource.
	Self *string `pulumi:"self"`
	// The current state of the resource.
	State *string `pulumi:"state"`
	// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
	SubnetId *string `pulumi:"subnetId"`
	// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type DnsResolverEndpointState struct {
	// The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver's compartment is changed.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
	EndpointType pulumi.StringPtrInput
	// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
	ForwardingAddress pulumi.StringPtrInput
	// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
	IsForwarding pulumi.BoolPtrInput
	// A Boolean flag indicating whether or not the resolver endpoint is for listening.
	IsListening pulumi.BoolPtrInput
	// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
	ListeningAddress pulumi.StringPtrInput
	// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
	Name pulumi.StringPtrInput
	// An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
	NsgIds pulumi.StringArrayInput
	// The OCID of the target resolver.
	ResolverId pulumi.StringPtrInput
	// Value must be `PRIVATE` when creating private name resolver endpoints.
	Scope pulumi.StringPtrInput
	// The canonical absolute URL of the resource.
	Self pulumi.StringPtrInput
	// The current state of the resource.
	State pulumi.StringPtrInput
	// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
	SubnetId pulumi.StringPtrInput
	// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
	TimeCreated pulumi.StringPtrInput
	// The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
	TimeUpdated pulumi.StringPtrInput
}

func (DnsResolverEndpointState) ElementType() reflect.Type {
	return reflect.TypeOf((*dnsResolverEndpointState)(nil)).Elem()
}

type dnsResolverEndpointArgs struct {
	// (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
	EndpointType *string `pulumi:"endpointType"`
	// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
	ForwardingAddress *string `pulumi:"forwardingAddress"`
	// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
	IsForwarding bool `pulumi:"isForwarding"`
	// A Boolean flag indicating whether or not the resolver endpoint is for listening.
	IsListening bool `pulumi:"isListening"`
	// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
	ListeningAddress *string `pulumi:"listeningAddress"`
	// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
	Name *string `pulumi:"name"`
	// An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
	NsgIds []string `pulumi:"nsgIds"`
	// The OCID of the target resolver.
	ResolverId string `pulumi:"resolverId"`
	// Value must be `PRIVATE` when creating private name resolver endpoints.
	Scope string `pulumi:"scope"`
	// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
	SubnetId string `pulumi:"subnetId"`
}

// The set of arguments for constructing a DnsResolverEndpoint resource.
type DnsResolverEndpointArgs struct {
	// (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
	EndpointType pulumi.StringPtrInput
	// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
	ForwardingAddress pulumi.StringPtrInput
	// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
	IsForwarding pulumi.BoolInput
	// A Boolean flag indicating whether or not the resolver endpoint is for listening.
	IsListening pulumi.BoolInput
	// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
	ListeningAddress pulumi.StringPtrInput
	// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
	Name pulumi.StringPtrInput
	// An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
	NsgIds pulumi.StringArrayInput
	// The OCID of the target resolver.
	ResolverId pulumi.StringInput
	// Value must be `PRIVATE` when creating private name resolver endpoints.
	Scope pulumi.StringInput
	// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
	SubnetId pulumi.StringInput
}

func (DnsResolverEndpointArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*dnsResolverEndpointArgs)(nil)).Elem()
}

type DnsResolverEndpointInput interface {
	pulumi.Input

	ToDnsResolverEndpointOutput() DnsResolverEndpointOutput
	ToDnsResolverEndpointOutputWithContext(ctx context.Context) DnsResolverEndpointOutput
}

func (*DnsResolverEndpoint) ElementType() reflect.Type {
	return reflect.TypeOf((*DnsResolverEndpoint)(nil))
}

func (i *DnsResolverEndpoint) ToDnsResolverEndpointOutput() DnsResolverEndpointOutput {
	return i.ToDnsResolverEndpointOutputWithContext(context.Background())
}

func (i *DnsResolverEndpoint) ToDnsResolverEndpointOutputWithContext(ctx context.Context) DnsResolverEndpointOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DnsResolverEndpointOutput)
}

func (i *DnsResolverEndpoint) ToDnsResolverEndpointPtrOutput() DnsResolverEndpointPtrOutput {
	return i.ToDnsResolverEndpointPtrOutputWithContext(context.Background())
}

func (i *DnsResolverEndpoint) ToDnsResolverEndpointPtrOutputWithContext(ctx context.Context) DnsResolverEndpointPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DnsResolverEndpointPtrOutput)
}

type DnsResolverEndpointPtrInput interface {
	pulumi.Input

	ToDnsResolverEndpointPtrOutput() DnsResolverEndpointPtrOutput
	ToDnsResolverEndpointPtrOutputWithContext(ctx context.Context) DnsResolverEndpointPtrOutput
}

type dnsResolverEndpointPtrType DnsResolverEndpointArgs

func (*dnsResolverEndpointPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**DnsResolverEndpoint)(nil))
}

func (i *dnsResolverEndpointPtrType) ToDnsResolverEndpointPtrOutput() DnsResolverEndpointPtrOutput {
	return i.ToDnsResolverEndpointPtrOutputWithContext(context.Background())
}

func (i *dnsResolverEndpointPtrType) ToDnsResolverEndpointPtrOutputWithContext(ctx context.Context) DnsResolverEndpointPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DnsResolverEndpointPtrOutput)
}

// DnsResolverEndpointArrayInput is an input type that accepts DnsResolverEndpointArray and DnsResolverEndpointArrayOutput values.
// You can construct a concrete instance of `DnsResolverEndpointArrayInput` via:
//
//          DnsResolverEndpointArray{ DnsResolverEndpointArgs{...} }
type DnsResolverEndpointArrayInput interface {
	pulumi.Input

	ToDnsResolverEndpointArrayOutput() DnsResolverEndpointArrayOutput
	ToDnsResolverEndpointArrayOutputWithContext(context.Context) DnsResolverEndpointArrayOutput
}

type DnsResolverEndpointArray []DnsResolverEndpointInput

func (DnsResolverEndpointArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DnsResolverEndpoint)(nil)).Elem()
}

func (i DnsResolverEndpointArray) ToDnsResolverEndpointArrayOutput() DnsResolverEndpointArrayOutput {
	return i.ToDnsResolverEndpointArrayOutputWithContext(context.Background())
}

func (i DnsResolverEndpointArray) ToDnsResolverEndpointArrayOutputWithContext(ctx context.Context) DnsResolverEndpointArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DnsResolverEndpointArrayOutput)
}

// DnsResolverEndpointMapInput is an input type that accepts DnsResolverEndpointMap and DnsResolverEndpointMapOutput values.
// You can construct a concrete instance of `DnsResolverEndpointMapInput` via:
//
//          DnsResolverEndpointMap{ "key": DnsResolverEndpointArgs{...} }
type DnsResolverEndpointMapInput interface {
	pulumi.Input

	ToDnsResolverEndpointMapOutput() DnsResolverEndpointMapOutput
	ToDnsResolverEndpointMapOutputWithContext(context.Context) DnsResolverEndpointMapOutput
}

type DnsResolverEndpointMap map[string]DnsResolverEndpointInput

func (DnsResolverEndpointMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DnsResolverEndpoint)(nil)).Elem()
}

func (i DnsResolverEndpointMap) ToDnsResolverEndpointMapOutput() DnsResolverEndpointMapOutput {
	return i.ToDnsResolverEndpointMapOutputWithContext(context.Background())
}

func (i DnsResolverEndpointMap) ToDnsResolverEndpointMapOutputWithContext(ctx context.Context) DnsResolverEndpointMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DnsResolverEndpointMapOutput)
}

type DnsResolverEndpointOutput struct {
	*pulumi.OutputState
}

func (DnsResolverEndpointOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*DnsResolverEndpoint)(nil))
}

func (o DnsResolverEndpointOutput) ToDnsResolverEndpointOutput() DnsResolverEndpointOutput {
	return o
}

func (o DnsResolverEndpointOutput) ToDnsResolverEndpointOutputWithContext(ctx context.Context) DnsResolverEndpointOutput {
	return o
}

func (o DnsResolverEndpointOutput) ToDnsResolverEndpointPtrOutput() DnsResolverEndpointPtrOutput {
	return o.ToDnsResolverEndpointPtrOutputWithContext(context.Background())
}

func (o DnsResolverEndpointOutput) ToDnsResolverEndpointPtrOutputWithContext(ctx context.Context) DnsResolverEndpointPtrOutput {
	return o.ApplyT(func(v DnsResolverEndpoint) *DnsResolverEndpoint {
		return &v
	}).(DnsResolverEndpointPtrOutput)
}

type DnsResolverEndpointPtrOutput struct {
	*pulumi.OutputState
}

func (DnsResolverEndpointPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DnsResolverEndpoint)(nil))
}

func (o DnsResolverEndpointPtrOutput) ToDnsResolverEndpointPtrOutput() DnsResolverEndpointPtrOutput {
	return o
}

func (o DnsResolverEndpointPtrOutput) ToDnsResolverEndpointPtrOutputWithContext(ctx context.Context) DnsResolverEndpointPtrOutput {
	return o
}

type DnsResolverEndpointArrayOutput struct{ *pulumi.OutputState }

func (DnsResolverEndpointArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]DnsResolverEndpoint)(nil))
}

func (o DnsResolverEndpointArrayOutput) ToDnsResolverEndpointArrayOutput() DnsResolverEndpointArrayOutput {
	return o
}

func (o DnsResolverEndpointArrayOutput) ToDnsResolverEndpointArrayOutputWithContext(ctx context.Context) DnsResolverEndpointArrayOutput {
	return o
}

func (o DnsResolverEndpointArrayOutput) Index(i pulumi.IntInput) DnsResolverEndpointOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) DnsResolverEndpoint {
		return vs[0].([]DnsResolverEndpoint)[vs[1].(int)]
	}).(DnsResolverEndpointOutput)
}

type DnsResolverEndpointMapOutput struct{ *pulumi.OutputState }

func (DnsResolverEndpointMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]DnsResolverEndpoint)(nil))
}

func (o DnsResolverEndpointMapOutput) ToDnsResolverEndpointMapOutput() DnsResolverEndpointMapOutput {
	return o
}

func (o DnsResolverEndpointMapOutput) ToDnsResolverEndpointMapOutputWithContext(ctx context.Context) DnsResolverEndpointMapOutput {
	return o
}

func (o DnsResolverEndpointMapOutput) MapIndex(k pulumi.StringInput) DnsResolverEndpointOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) DnsResolverEndpoint {
		return vs[0].(map[string]DnsResolverEndpoint)[vs[1].(string)]
	}).(DnsResolverEndpointOutput)
}

func init() {
	pulumi.RegisterOutputType(DnsResolverEndpointOutput{})
	pulumi.RegisterOutputType(DnsResolverEndpointPtrOutput{})
	pulumi.RegisterOutputType(DnsResolverEndpointArrayOutput{})
	pulumi.RegisterOutputType(DnsResolverEndpointMapOutput{})
}