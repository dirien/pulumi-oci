// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// ## Import
//
// Hostnames can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/loadBalancerHostname:LoadBalancerHostname test_hostname "loadBalancers/{loadBalancerId}/hostnames/{name}"
// ```
type LoadBalancerHostname struct {
	pulumi.CustomResourceState

	// (Updatable) A virtual hostname. For more information about virtual hostname string construction, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm#routing).  Example: `app.example.com`
	Hostname pulumi.StringOutput `pulumi:"hostname"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the hostname to.
	LoadBalancerId pulumi.StringOutput `pulumi:"loadBalancerId"`
	// A friendly name for the hostname resource. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleHostname001`
	Name  pulumi.StringOutput `pulumi:"name"`
	State pulumi.StringOutput `pulumi:"state"`
}

// NewLoadBalancerHostname registers a new resource with the given unique name, arguments, and options.
func NewLoadBalancerHostname(ctx *pulumi.Context,
	name string, args *LoadBalancerHostnameArgs, opts ...pulumi.ResourceOption) (*LoadBalancerHostname, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Hostname == nil {
		return nil, errors.New("invalid value for required argument 'Hostname'")
	}
	if args.LoadBalancerId == nil {
		return nil, errors.New("invalid value for required argument 'LoadBalancerId'")
	}
	var resource LoadBalancerHostname
	err := ctx.RegisterResource("oci:index/loadBalancerHostname:LoadBalancerHostname", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLoadBalancerHostname gets an existing LoadBalancerHostname resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLoadBalancerHostname(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LoadBalancerHostnameState, opts ...pulumi.ResourceOption) (*LoadBalancerHostname, error) {
	var resource LoadBalancerHostname
	err := ctx.ReadResource("oci:index/loadBalancerHostname:LoadBalancerHostname", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LoadBalancerHostname resources.
type loadBalancerHostnameState struct {
	// (Updatable) A virtual hostname. For more information about virtual hostname string construction, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm#routing).  Example: `app.example.com`
	Hostname *string `pulumi:"hostname"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the hostname to.
	LoadBalancerId *string `pulumi:"loadBalancerId"`
	// A friendly name for the hostname resource. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleHostname001`
	Name  *string `pulumi:"name"`
	State *string `pulumi:"state"`
}

type LoadBalancerHostnameState struct {
	// (Updatable) A virtual hostname. For more information about virtual hostname string construction, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm#routing).  Example: `app.example.com`
	Hostname pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the hostname to.
	LoadBalancerId pulumi.StringPtrInput
	// A friendly name for the hostname resource. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleHostname001`
	Name  pulumi.StringPtrInput
	State pulumi.StringPtrInput
}

func (LoadBalancerHostnameState) ElementType() reflect.Type {
	return reflect.TypeOf((*loadBalancerHostnameState)(nil)).Elem()
}

type loadBalancerHostnameArgs struct {
	// (Updatable) A virtual hostname. For more information about virtual hostname string construction, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm#routing).  Example: `app.example.com`
	Hostname string `pulumi:"hostname"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the hostname to.
	LoadBalancerId string `pulumi:"loadBalancerId"`
	// A friendly name for the hostname resource. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleHostname001`
	Name *string `pulumi:"name"`
}

// The set of arguments for constructing a LoadBalancerHostname resource.
type LoadBalancerHostnameArgs struct {
	// (Updatable) A virtual hostname. For more information about virtual hostname string construction, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm#routing).  Example: `app.example.com`
	Hostname pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the hostname to.
	LoadBalancerId pulumi.StringInput
	// A friendly name for the hostname resource. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleHostname001`
	Name pulumi.StringPtrInput
}

func (LoadBalancerHostnameArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*loadBalancerHostnameArgs)(nil)).Elem()
}

type LoadBalancerHostnameInput interface {
	pulumi.Input

	ToLoadBalancerHostnameOutput() LoadBalancerHostnameOutput
	ToLoadBalancerHostnameOutputWithContext(ctx context.Context) LoadBalancerHostnameOutput
}

func (*LoadBalancerHostname) ElementType() reflect.Type {
	return reflect.TypeOf((*LoadBalancerHostname)(nil))
}

func (i *LoadBalancerHostname) ToLoadBalancerHostnameOutput() LoadBalancerHostnameOutput {
	return i.ToLoadBalancerHostnameOutputWithContext(context.Background())
}

func (i *LoadBalancerHostname) ToLoadBalancerHostnameOutputWithContext(ctx context.Context) LoadBalancerHostnameOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerHostnameOutput)
}

func (i *LoadBalancerHostname) ToLoadBalancerHostnamePtrOutput() LoadBalancerHostnamePtrOutput {
	return i.ToLoadBalancerHostnamePtrOutputWithContext(context.Background())
}

func (i *LoadBalancerHostname) ToLoadBalancerHostnamePtrOutputWithContext(ctx context.Context) LoadBalancerHostnamePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerHostnamePtrOutput)
}

type LoadBalancerHostnamePtrInput interface {
	pulumi.Input

	ToLoadBalancerHostnamePtrOutput() LoadBalancerHostnamePtrOutput
	ToLoadBalancerHostnamePtrOutputWithContext(ctx context.Context) LoadBalancerHostnamePtrOutput
}

type loadBalancerHostnamePtrType LoadBalancerHostnameArgs

func (*loadBalancerHostnamePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**LoadBalancerHostname)(nil))
}

func (i *loadBalancerHostnamePtrType) ToLoadBalancerHostnamePtrOutput() LoadBalancerHostnamePtrOutput {
	return i.ToLoadBalancerHostnamePtrOutputWithContext(context.Background())
}

func (i *loadBalancerHostnamePtrType) ToLoadBalancerHostnamePtrOutputWithContext(ctx context.Context) LoadBalancerHostnamePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerHostnamePtrOutput)
}

// LoadBalancerHostnameArrayInput is an input type that accepts LoadBalancerHostnameArray and LoadBalancerHostnameArrayOutput values.
// You can construct a concrete instance of `LoadBalancerHostnameArrayInput` via:
//
//          LoadBalancerHostnameArray{ LoadBalancerHostnameArgs{...} }
type LoadBalancerHostnameArrayInput interface {
	pulumi.Input

	ToLoadBalancerHostnameArrayOutput() LoadBalancerHostnameArrayOutput
	ToLoadBalancerHostnameArrayOutputWithContext(context.Context) LoadBalancerHostnameArrayOutput
}

type LoadBalancerHostnameArray []LoadBalancerHostnameInput

func (LoadBalancerHostnameArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LoadBalancerHostname)(nil)).Elem()
}

func (i LoadBalancerHostnameArray) ToLoadBalancerHostnameArrayOutput() LoadBalancerHostnameArrayOutput {
	return i.ToLoadBalancerHostnameArrayOutputWithContext(context.Background())
}

func (i LoadBalancerHostnameArray) ToLoadBalancerHostnameArrayOutputWithContext(ctx context.Context) LoadBalancerHostnameArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerHostnameArrayOutput)
}

// LoadBalancerHostnameMapInput is an input type that accepts LoadBalancerHostnameMap and LoadBalancerHostnameMapOutput values.
// You can construct a concrete instance of `LoadBalancerHostnameMapInput` via:
//
//          LoadBalancerHostnameMap{ "key": LoadBalancerHostnameArgs{...} }
type LoadBalancerHostnameMapInput interface {
	pulumi.Input

	ToLoadBalancerHostnameMapOutput() LoadBalancerHostnameMapOutput
	ToLoadBalancerHostnameMapOutputWithContext(context.Context) LoadBalancerHostnameMapOutput
}

type LoadBalancerHostnameMap map[string]LoadBalancerHostnameInput

func (LoadBalancerHostnameMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LoadBalancerHostname)(nil)).Elem()
}

func (i LoadBalancerHostnameMap) ToLoadBalancerHostnameMapOutput() LoadBalancerHostnameMapOutput {
	return i.ToLoadBalancerHostnameMapOutputWithContext(context.Background())
}

func (i LoadBalancerHostnameMap) ToLoadBalancerHostnameMapOutputWithContext(ctx context.Context) LoadBalancerHostnameMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerHostnameMapOutput)
}

type LoadBalancerHostnameOutput struct {
	*pulumi.OutputState
}

func (LoadBalancerHostnameOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LoadBalancerHostname)(nil))
}

func (o LoadBalancerHostnameOutput) ToLoadBalancerHostnameOutput() LoadBalancerHostnameOutput {
	return o
}

func (o LoadBalancerHostnameOutput) ToLoadBalancerHostnameOutputWithContext(ctx context.Context) LoadBalancerHostnameOutput {
	return o
}

func (o LoadBalancerHostnameOutput) ToLoadBalancerHostnamePtrOutput() LoadBalancerHostnamePtrOutput {
	return o.ToLoadBalancerHostnamePtrOutputWithContext(context.Background())
}

func (o LoadBalancerHostnameOutput) ToLoadBalancerHostnamePtrOutputWithContext(ctx context.Context) LoadBalancerHostnamePtrOutput {
	return o.ApplyT(func(v LoadBalancerHostname) *LoadBalancerHostname {
		return &v
	}).(LoadBalancerHostnamePtrOutput)
}

type LoadBalancerHostnamePtrOutput struct {
	*pulumi.OutputState
}

func (LoadBalancerHostnamePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**LoadBalancerHostname)(nil))
}

func (o LoadBalancerHostnamePtrOutput) ToLoadBalancerHostnamePtrOutput() LoadBalancerHostnamePtrOutput {
	return o
}

func (o LoadBalancerHostnamePtrOutput) ToLoadBalancerHostnamePtrOutputWithContext(ctx context.Context) LoadBalancerHostnamePtrOutput {
	return o
}

type LoadBalancerHostnameArrayOutput struct{ *pulumi.OutputState }

func (LoadBalancerHostnameArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]LoadBalancerHostname)(nil))
}

func (o LoadBalancerHostnameArrayOutput) ToLoadBalancerHostnameArrayOutput() LoadBalancerHostnameArrayOutput {
	return o
}

func (o LoadBalancerHostnameArrayOutput) ToLoadBalancerHostnameArrayOutputWithContext(ctx context.Context) LoadBalancerHostnameArrayOutput {
	return o
}

func (o LoadBalancerHostnameArrayOutput) Index(i pulumi.IntInput) LoadBalancerHostnameOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) LoadBalancerHostname {
		return vs[0].([]LoadBalancerHostname)[vs[1].(int)]
	}).(LoadBalancerHostnameOutput)
}

type LoadBalancerHostnameMapOutput struct{ *pulumi.OutputState }

func (LoadBalancerHostnameMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]LoadBalancerHostname)(nil))
}

func (o LoadBalancerHostnameMapOutput) ToLoadBalancerHostnameMapOutput() LoadBalancerHostnameMapOutput {
	return o
}

func (o LoadBalancerHostnameMapOutput) ToLoadBalancerHostnameMapOutputWithContext(ctx context.Context) LoadBalancerHostnameMapOutput {
	return o
}

func (o LoadBalancerHostnameMapOutput) MapIndex(k pulumi.StringInput) LoadBalancerHostnameOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) LoadBalancerHostname {
		return vs[0].(map[string]LoadBalancerHostname)[vs[1].(string)]
	}).(LoadBalancerHostnameOutput)
}

func init() {
	pulumi.RegisterOutputType(LoadBalancerHostnameOutput{})
	pulumi.RegisterOutputType(LoadBalancerHostnamePtrOutput{})
	pulumi.RegisterOutputType(LoadBalancerHostnameArrayOutput{})
	pulumi.RegisterOutputType(LoadBalancerHostnameMapOutput{})
}
