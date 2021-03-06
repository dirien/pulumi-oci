// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Backend resource in Oracle Cloud Infrastructure Load Balancer service.
//
// Adds a backend server to a backend set.
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
// 		_, err := oci.NewLoadBalancerBackend(ctx, "testBackend", &oci.LoadBalancerBackendArgs{
// 			BackendsetName: pulumi.Any(oci_load_balancer_backend_set.Test_backend_set.Name),
// 			IpAddress:      pulumi.Any(_var.Backend_ip_address),
// 			LoadBalancerId: pulumi.Any(oci_load_balancer_load_balancer.Test_load_balancer.Id),
// 			Port:           pulumi.Any(_var.Backend_port),
// 			Backup:         pulumi.Any(_var.Backend_backup),
// 			Drain:          pulumi.Any(_var.Backend_drain),
// 			Offline:        pulumi.Any(_var.Backend_offline),
// 			Weight:         pulumi.Any(_var.Backend_weight),
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
// Backends can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/loadBalancerBackend:LoadBalancerBackend test_backend "loadBalancers/{loadBalancerId}/backendSets/{backendSetName}/backends/{backendName}"
// ```
type LoadBalancerBackend struct {
	pulumi.CustomResourceState

	// The name of the backend set to add the backend server to.  Example: `exampleBackendSet`
	BackendsetName pulumi.StringOutput `pulumi:"backendsetName"`
	// (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as "backup" fail the health check policy.
	Backup pulumi.BoolPtrOutput `pulumi:"backup"`
	// (Updatable) Whether the load balancer should drain this server. Servers marked "drain" receive no new incoming traffic.  Example: `false`
	Drain pulumi.BoolOutput `pulumi:"drain"`
	// The IP address of the backend server.  Example: `10.0.0.3`
	IpAddress pulumi.StringOutput `pulumi:"ipAddress"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
	LoadBalancerId pulumi.StringOutput `pulumi:"loadBalancerId"`
	// A read-only field showing the IP address and port that uniquely identify this backend server in the backend set.  Example: `10.0.0.3:8080`
	Name pulumi.StringOutput `pulumi:"name"`
	// (Updatable) Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
	Offline pulumi.BoolOutput `pulumi:"offline"`
	// The communication port for the backend server.  Example: `8080`
	Port  pulumi.IntOutput    `pulumi:"port"`
	State pulumi.StringOutput `pulumi:"state"`
	// (Updatable) The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted '3' receives 3 times the number of new connections as a server weighted '1'. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
	Weight pulumi.IntOutput `pulumi:"weight"`
}

// NewLoadBalancerBackend registers a new resource with the given unique name, arguments, and options.
func NewLoadBalancerBackend(ctx *pulumi.Context,
	name string, args *LoadBalancerBackendArgs, opts ...pulumi.ResourceOption) (*LoadBalancerBackend, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.BackendsetName == nil {
		return nil, errors.New("invalid value for required argument 'BackendsetName'")
	}
	if args.IpAddress == nil {
		return nil, errors.New("invalid value for required argument 'IpAddress'")
	}
	if args.LoadBalancerId == nil {
		return nil, errors.New("invalid value for required argument 'LoadBalancerId'")
	}
	if args.Port == nil {
		return nil, errors.New("invalid value for required argument 'Port'")
	}
	var resource LoadBalancerBackend
	err := ctx.RegisterResource("oci:index/loadBalancerBackend:LoadBalancerBackend", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLoadBalancerBackend gets an existing LoadBalancerBackend resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLoadBalancerBackend(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LoadBalancerBackendState, opts ...pulumi.ResourceOption) (*LoadBalancerBackend, error) {
	var resource LoadBalancerBackend
	err := ctx.ReadResource("oci:index/loadBalancerBackend:LoadBalancerBackend", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LoadBalancerBackend resources.
type loadBalancerBackendState struct {
	// The name of the backend set to add the backend server to.  Example: `exampleBackendSet`
	BackendsetName *string `pulumi:"backendsetName"`
	// (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as "backup" fail the health check policy.
	Backup *bool `pulumi:"backup"`
	// (Updatable) Whether the load balancer should drain this server. Servers marked "drain" receive no new incoming traffic.  Example: `false`
	Drain *bool `pulumi:"drain"`
	// The IP address of the backend server.  Example: `10.0.0.3`
	IpAddress *string `pulumi:"ipAddress"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
	LoadBalancerId *string `pulumi:"loadBalancerId"`
	// A read-only field showing the IP address and port that uniquely identify this backend server in the backend set.  Example: `10.0.0.3:8080`
	Name *string `pulumi:"name"`
	// (Updatable) Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
	Offline *bool `pulumi:"offline"`
	// The communication port for the backend server.  Example: `8080`
	Port  *int    `pulumi:"port"`
	State *string `pulumi:"state"`
	// (Updatable) The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted '3' receives 3 times the number of new connections as a server weighted '1'. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
	Weight *int `pulumi:"weight"`
}

type LoadBalancerBackendState struct {
	// The name of the backend set to add the backend server to.  Example: `exampleBackendSet`
	BackendsetName pulumi.StringPtrInput
	// (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as "backup" fail the health check policy.
	Backup pulumi.BoolPtrInput
	// (Updatable) Whether the load balancer should drain this server. Servers marked "drain" receive no new incoming traffic.  Example: `false`
	Drain pulumi.BoolPtrInput
	// The IP address of the backend server.  Example: `10.0.0.3`
	IpAddress pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
	LoadBalancerId pulumi.StringPtrInput
	// A read-only field showing the IP address and port that uniquely identify this backend server in the backend set.  Example: `10.0.0.3:8080`
	Name pulumi.StringPtrInput
	// (Updatable) Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
	Offline pulumi.BoolPtrInput
	// The communication port for the backend server.  Example: `8080`
	Port  pulumi.IntPtrInput
	State pulumi.StringPtrInput
	// (Updatable) The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted '3' receives 3 times the number of new connections as a server weighted '1'. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
	Weight pulumi.IntPtrInput
}

func (LoadBalancerBackendState) ElementType() reflect.Type {
	return reflect.TypeOf((*loadBalancerBackendState)(nil)).Elem()
}

type loadBalancerBackendArgs struct {
	// The name of the backend set to add the backend server to.  Example: `exampleBackendSet`
	BackendsetName string `pulumi:"backendsetName"`
	// (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as "backup" fail the health check policy.
	Backup *bool `pulumi:"backup"`
	// (Updatable) Whether the load balancer should drain this server. Servers marked "drain" receive no new incoming traffic.  Example: `false`
	Drain *bool `pulumi:"drain"`
	// The IP address of the backend server.  Example: `10.0.0.3`
	IpAddress string `pulumi:"ipAddress"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
	LoadBalancerId string `pulumi:"loadBalancerId"`
	// (Updatable) Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
	Offline *bool `pulumi:"offline"`
	// The communication port for the backend server.  Example: `8080`
	Port int `pulumi:"port"`
	// (Updatable) The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted '3' receives 3 times the number of new connections as a server weighted '1'. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
	Weight *int `pulumi:"weight"`
}

// The set of arguments for constructing a LoadBalancerBackend resource.
type LoadBalancerBackendArgs struct {
	// The name of the backend set to add the backend server to.  Example: `exampleBackendSet`
	BackendsetName pulumi.StringInput
	// (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as "backup" fail the health check policy.
	Backup pulumi.BoolPtrInput
	// (Updatable) Whether the load balancer should drain this server. Servers marked "drain" receive no new incoming traffic.  Example: `false`
	Drain pulumi.BoolPtrInput
	// The IP address of the backend server.  Example: `10.0.0.3`
	IpAddress pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
	LoadBalancerId pulumi.StringInput
	// (Updatable) Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
	Offline pulumi.BoolPtrInput
	// The communication port for the backend server.  Example: `8080`
	Port pulumi.IntInput
	// (Updatable) The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted '3' receives 3 times the number of new connections as a server weighted '1'. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
	Weight pulumi.IntPtrInput
}

func (LoadBalancerBackendArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*loadBalancerBackendArgs)(nil)).Elem()
}

type LoadBalancerBackendInput interface {
	pulumi.Input

	ToLoadBalancerBackendOutput() LoadBalancerBackendOutput
	ToLoadBalancerBackendOutputWithContext(ctx context.Context) LoadBalancerBackendOutput
}

func (*LoadBalancerBackend) ElementType() reflect.Type {
	return reflect.TypeOf((*LoadBalancerBackend)(nil))
}

func (i *LoadBalancerBackend) ToLoadBalancerBackendOutput() LoadBalancerBackendOutput {
	return i.ToLoadBalancerBackendOutputWithContext(context.Background())
}

func (i *LoadBalancerBackend) ToLoadBalancerBackendOutputWithContext(ctx context.Context) LoadBalancerBackendOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerBackendOutput)
}

func (i *LoadBalancerBackend) ToLoadBalancerBackendPtrOutput() LoadBalancerBackendPtrOutput {
	return i.ToLoadBalancerBackendPtrOutputWithContext(context.Background())
}

func (i *LoadBalancerBackend) ToLoadBalancerBackendPtrOutputWithContext(ctx context.Context) LoadBalancerBackendPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerBackendPtrOutput)
}

type LoadBalancerBackendPtrInput interface {
	pulumi.Input

	ToLoadBalancerBackendPtrOutput() LoadBalancerBackendPtrOutput
	ToLoadBalancerBackendPtrOutputWithContext(ctx context.Context) LoadBalancerBackendPtrOutput
}

type loadBalancerBackendPtrType LoadBalancerBackendArgs

func (*loadBalancerBackendPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**LoadBalancerBackend)(nil))
}

func (i *loadBalancerBackendPtrType) ToLoadBalancerBackendPtrOutput() LoadBalancerBackendPtrOutput {
	return i.ToLoadBalancerBackendPtrOutputWithContext(context.Background())
}

func (i *loadBalancerBackendPtrType) ToLoadBalancerBackendPtrOutputWithContext(ctx context.Context) LoadBalancerBackendPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerBackendPtrOutput)
}

// LoadBalancerBackendArrayInput is an input type that accepts LoadBalancerBackendArray and LoadBalancerBackendArrayOutput values.
// You can construct a concrete instance of `LoadBalancerBackendArrayInput` via:
//
//          LoadBalancerBackendArray{ LoadBalancerBackendArgs{...} }
type LoadBalancerBackendArrayInput interface {
	pulumi.Input

	ToLoadBalancerBackendArrayOutput() LoadBalancerBackendArrayOutput
	ToLoadBalancerBackendArrayOutputWithContext(context.Context) LoadBalancerBackendArrayOutput
}

type LoadBalancerBackendArray []LoadBalancerBackendInput

func (LoadBalancerBackendArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LoadBalancerBackend)(nil)).Elem()
}

func (i LoadBalancerBackendArray) ToLoadBalancerBackendArrayOutput() LoadBalancerBackendArrayOutput {
	return i.ToLoadBalancerBackendArrayOutputWithContext(context.Background())
}

func (i LoadBalancerBackendArray) ToLoadBalancerBackendArrayOutputWithContext(ctx context.Context) LoadBalancerBackendArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerBackendArrayOutput)
}

// LoadBalancerBackendMapInput is an input type that accepts LoadBalancerBackendMap and LoadBalancerBackendMapOutput values.
// You can construct a concrete instance of `LoadBalancerBackendMapInput` via:
//
//          LoadBalancerBackendMap{ "key": LoadBalancerBackendArgs{...} }
type LoadBalancerBackendMapInput interface {
	pulumi.Input

	ToLoadBalancerBackendMapOutput() LoadBalancerBackendMapOutput
	ToLoadBalancerBackendMapOutputWithContext(context.Context) LoadBalancerBackendMapOutput
}

type LoadBalancerBackendMap map[string]LoadBalancerBackendInput

func (LoadBalancerBackendMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LoadBalancerBackend)(nil)).Elem()
}

func (i LoadBalancerBackendMap) ToLoadBalancerBackendMapOutput() LoadBalancerBackendMapOutput {
	return i.ToLoadBalancerBackendMapOutputWithContext(context.Background())
}

func (i LoadBalancerBackendMap) ToLoadBalancerBackendMapOutputWithContext(ctx context.Context) LoadBalancerBackendMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerBackendMapOutput)
}

type LoadBalancerBackendOutput struct {
	*pulumi.OutputState
}

func (LoadBalancerBackendOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LoadBalancerBackend)(nil))
}

func (o LoadBalancerBackendOutput) ToLoadBalancerBackendOutput() LoadBalancerBackendOutput {
	return o
}

func (o LoadBalancerBackendOutput) ToLoadBalancerBackendOutputWithContext(ctx context.Context) LoadBalancerBackendOutput {
	return o
}

func (o LoadBalancerBackendOutput) ToLoadBalancerBackendPtrOutput() LoadBalancerBackendPtrOutput {
	return o.ToLoadBalancerBackendPtrOutputWithContext(context.Background())
}

func (o LoadBalancerBackendOutput) ToLoadBalancerBackendPtrOutputWithContext(ctx context.Context) LoadBalancerBackendPtrOutput {
	return o.ApplyT(func(v LoadBalancerBackend) *LoadBalancerBackend {
		return &v
	}).(LoadBalancerBackendPtrOutput)
}

type LoadBalancerBackendPtrOutput struct {
	*pulumi.OutputState
}

func (LoadBalancerBackendPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**LoadBalancerBackend)(nil))
}

func (o LoadBalancerBackendPtrOutput) ToLoadBalancerBackendPtrOutput() LoadBalancerBackendPtrOutput {
	return o
}

func (o LoadBalancerBackendPtrOutput) ToLoadBalancerBackendPtrOutputWithContext(ctx context.Context) LoadBalancerBackendPtrOutput {
	return o
}

type LoadBalancerBackendArrayOutput struct{ *pulumi.OutputState }

func (LoadBalancerBackendArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]LoadBalancerBackend)(nil))
}

func (o LoadBalancerBackendArrayOutput) ToLoadBalancerBackendArrayOutput() LoadBalancerBackendArrayOutput {
	return o
}

func (o LoadBalancerBackendArrayOutput) ToLoadBalancerBackendArrayOutputWithContext(ctx context.Context) LoadBalancerBackendArrayOutput {
	return o
}

func (o LoadBalancerBackendArrayOutput) Index(i pulumi.IntInput) LoadBalancerBackendOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) LoadBalancerBackend {
		return vs[0].([]LoadBalancerBackend)[vs[1].(int)]
	}).(LoadBalancerBackendOutput)
}

type LoadBalancerBackendMapOutput struct{ *pulumi.OutputState }

func (LoadBalancerBackendMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]LoadBalancerBackend)(nil))
}

func (o LoadBalancerBackendMapOutput) ToLoadBalancerBackendMapOutput() LoadBalancerBackendMapOutput {
	return o
}

func (o LoadBalancerBackendMapOutput) ToLoadBalancerBackendMapOutputWithContext(ctx context.Context) LoadBalancerBackendMapOutput {
	return o
}

func (o LoadBalancerBackendMapOutput) MapIndex(k pulumi.StringInput) LoadBalancerBackendOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) LoadBalancerBackend {
		return vs[0].(map[string]LoadBalancerBackend)[vs[1].(string)]
	}).(LoadBalancerBackendOutput)
}

func init() {
	pulumi.RegisterOutputType(LoadBalancerBackendOutput{})
	pulumi.RegisterOutputType(LoadBalancerBackendPtrOutput{})
	pulumi.RegisterOutputType(LoadBalancerBackendArrayOutput{})
	pulumi.RegisterOutputType(LoadBalancerBackendMapOutput{})
}
