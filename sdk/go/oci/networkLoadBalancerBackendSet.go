// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Backend Set resource in Oracle Cloud Infrastructure Network Load Balancer service.
//
// Adds a backend set to a network load balancer.
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
// 		_, err := oci.NewNetworkLoadBalancerBackendSet(ctx, "testBackendSet", &oci.NetworkLoadBalancerBackendSetArgs{
// 			HealthChecker: &NetworkLoadBalancerBackendSetHealthCheckerArgs{
// 				Protocol:          pulumi.Any(_var.Backend_set_health_checker_protocol),
// 				IntervalInMillis:  pulumi.Any(_var.Backend_set_health_checker_interval_in_millis),
// 				Port:              pulumi.Any(_var.Backend_set_health_checker_port),
// 				RequestData:       pulumi.Any(_var.Backend_set_health_checker_request_data),
// 				ResponseBodyRegex: pulumi.Any(_var.Backend_set_health_checker_response_body_regex),
// 				ResponseData:      pulumi.Any(_var.Backend_set_health_checker_response_data),
// 				Retries:           pulumi.Any(_var.Backend_set_health_checker_retries),
// 				ReturnCode:        pulumi.Any(_var.Backend_set_health_checker_return_code),
// 				TimeoutInMillis:   pulumi.Any(_var.Backend_set_health_checker_timeout_in_millis),
// 				UrlPath:           pulumi.Any(_var.Backend_set_health_checker_url_path),
// 			},
// 			NetworkLoadBalancerId: pulumi.Any(oci_network_load_balancer_network_load_balancer.Test_network_load_balancer.Id),
// 			Policy:                pulumi.Any(_var.Backend_set_policy),
// 			IsPreserveSource:      pulumi.Any(_var.Backend_set_is_preserve_source),
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
// BackendSets can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/networkLoadBalancerBackendSet:NetworkLoadBalancerBackendSet test_backend_set "networkLoadBalancers/{networkLoadBalancerId}/backendSets/{backendSetName}"
// ```
type NetworkLoadBalancerBackendSet struct {
	pulumi.CustomResourceState

	// Array of backends.
	Backends NetworkLoadBalancerBackendSetBackendArrayOutput `pulumi:"backends"`
	// (Updatable) The health check policy configuration. For more information, see [Editing Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/editinghealthcheck.htm).
	HealthChecker NetworkLoadBalancerBackendSetHealthCheckerOutput `pulumi:"healthChecker"`
	// (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
	IsPreserveSource pulumi.BoolOutput `pulumi:"isPreserveSource"`
	// A user-friendly name for the backend set that must be unique and cannot be changed.
	Name pulumi.StringOutput `pulumi:"name"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
	NetworkLoadBalancerId pulumi.StringOutput `pulumi:"networkLoadBalancerId"`
	// (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE``
	Policy pulumi.StringOutput `pulumi:"policy"`
}

// NewNetworkLoadBalancerBackendSet registers a new resource with the given unique name, arguments, and options.
func NewNetworkLoadBalancerBackendSet(ctx *pulumi.Context,
	name string, args *NetworkLoadBalancerBackendSetArgs, opts ...pulumi.ResourceOption) (*NetworkLoadBalancerBackendSet, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.HealthChecker == nil {
		return nil, errors.New("invalid value for required argument 'HealthChecker'")
	}
	if args.NetworkLoadBalancerId == nil {
		return nil, errors.New("invalid value for required argument 'NetworkLoadBalancerId'")
	}
	if args.Policy == nil {
		return nil, errors.New("invalid value for required argument 'Policy'")
	}
	var resource NetworkLoadBalancerBackendSet
	err := ctx.RegisterResource("oci:index/networkLoadBalancerBackendSet:NetworkLoadBalancerBackendSet", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetNetworkLoadBalancerBackendSet gets an existing NetworkLoadBalancerBackendSet resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetNetworkLoadBalancerBackendSet(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *NetworkLoadBalancerBackendSetState, opts ...pulumi.ResourceOption) (*NetworkLoadBalancerBackendSet, error) {
	var resource NetworkLoadBalancerBackendSet
	err := ctx.ReadResource("oci:index/networkLoadBalancerBackendSet:NetworkLoadBalancerBackendSet", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering NetworkLoadBalancerBackendSet resources.
type networkLoadBalancerBackendSetState struct {
	// Array of backends.
	Backends []NetworkLoadBalancerBackendSetBackend `pulumi:"backends"`
	// (Updatable) The health check policy configuration. For more information, see [Editing Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/editinghealthcheck.htm).
	HealthChecker *NetworkLoadBalancerBackendSetHealthChecker `pulumi:"healthChecker"`
	// (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
	IsPreserveSource *bool `pulumi:"isPreserveSource"`
	// A user-friendly name for the backend set that must be unique and cannot be changed.
	Name *string `pulumi:"name"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
	NetworkLoadBalancerId *string `pulumi:"networkLoadBalancerId"`
	// (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE``
	Policy *string `pulumi:"policy"`
}

type NetworkLoadBalancerBackendSetState struct {
	// Array of backends.
	Backends NetworkLoadBalancerBackendSetBackendArrayInput
	// (Updatable) The health check policy configuration. For more information, see [Editing Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/editinghealthcheck.htm).
	HealthChecker NetworkLoadBalancerBackendSetHealthCheckerPtrInput
	// (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
	IsPreserveSource pulumi.BoolPtrInput
	// A user-friendly name for the backend set that must be unique and cannot be changed.
	Name pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
	NetworkLoadBalancerId pulumi.StringPtrInput
	// (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE``
	Policy pulumi.StringPtrInput
}

func (NetworkLoadBalancerBackendSetState) ElementType() reflect.Type {
	return reflect.TypeOf((*networkLoadBalancerBackendSetState)(nil)).Elem()
}

type networkLoadBalancerBackendSetArgs struct {
	// (Updatable) The health check policy configuration. For more information, see [Editing Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/editinghealthcheck.htm).
	HealthChecker NetworkLoadBalancerBackendSetHealthChecker `pulumi:"healthChecker"`
	// (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
	IsPreserveSource *bool `pulumi:"isPreserveSource"`
	// A user-friendly name for the backend set that must be unique and cannot be changed.
	Name *string `pulumi:"name"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
	NetworkLoadBalancerId string `pulumi:"networkLoadBalancerId"`
	// (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE``
	Policy string `pulumi:"policy"`
}

// The set of arguments for constructing a NetworkLoadBalancerBackendSet resource.
type NetworkLoadBalancerBackendSetArgs struct {
	// (Updatable) The health check policy configuration. For more information, see [Editing Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/editinghealthcheck.htm).
	HealthChecker NetworkLoadBalancerBackendSetHealthCheckerInput
	// (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
	IsPreserveSource pulumi.BoolPtrInput
	// A user-friendly name for the backend set that must be unique and cannot be changed.
	Name pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
	NetworkLoadBalancerId pulumi.StringInput
	// (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE``
	Policy pulumi.StringInput
}

func (NetworkLoadBalancerBackendSetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*networkLoadBalancerBackendSetArgs)(nil)).Elem()
}

type NetworkLoadBalancerBackendSetInput interface {
	pulumi.Input

	ToNetworkLoadBalancerBackendSetOutput() NetworkLoadBalancerBackendSetOutput
	ToNetworkLoadBalancerBackendSetOutputWithContext(ctx context.Context) NetworkLoadBalancerBackendSetOutput
}

func (*NetworkLoadBalancerBackendSet) ElementType() reflect.Type {
	return reflect.TypeOf((*NetworkLoadBalancerBackendSet)(nil))
}

func (i *NetworkLoadBalancerBackendSet) ToNetworkLoadBalancerBackendSetOutput() NetworkLoadBalancerBackendSetOutput {
	return i.ToNetworkLoadBalancerBackendSetOutputWithContext(context.Background())
}

func (i *NetworkLoadBalancerBackendSet) ToNetworkLoadBalancerBackendSetOutputWithContext(ctx context.Context) NetworkLoadBalancerBackendSetOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NetworkLoadBalancerBackendSetOutput)
}

func (i *NetworkLoadBalancerBackendSet) ToNetworkLoadBalancerBackendSetPtrOutput() NetworkLoadBalancerBackendSetPtrOutput {
	return i.ToNetworkLoadBalancerBackendSetPtrOutputWithContext(context.Background())
}

func (i *NetworkLoadBalancerBackendSet) ToNetworkLoadBalancerBackendSetPtrOutputWithContext(ctx context.Context) NetworkLoadBalancerBackendSetPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NetworkLoadBalancerBackendSetPtrOutput)
}

type NetworkLoadBalancerBackendSetPtrInput interface {
	pulumi.Input

	ToNetworkLoadBalancerBackendSetPtrOutput() NetworkLoadBalancerBackendSetPtrOutput
	ToNetworkLoadBalancerBackendSetPtrOutputWithContext(ctx context.Context) NetworkLoadBalancerBackendSetPtrOutput
}

type networkLoadBalancerBackendSetPtrType NetworkLoadBalancerBackendSetArgs

func (*networkLoadBalancerBackendSetPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**NetworkLoadBalancerBackendSet)(nil))
}

func (i *networkLoadBalancerBackendSetPtrType) ToNetworkLoadBalancerBackendSetPtrOutput() NetworkLoadBalancerBackendSetPtrOutput {
	return i.ToNetworkLoadBalancerBackendSetPtrOutputWithContext(context.Background())
}

func (i *networkLoadBalancerBackendSetPtrType) ToNetworkLoadBalancerBackendSetPtrOutputWithContext(ctx context.Context) NetworkLoadBalancerBackendSetPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NetworkLoadBalancerBackendSetPtrOutput)
}

// NetworkLoadBalancerBackendSetArrayInput is an input type that accepts NetworkLoadBalancerBackendSetArray and NetworkLoadBalancerBackendSetArrayOutput values.
// You can construct a concrete instance of `NetworkLoadBalancerBackendSetArrayInput` via:
//
//          NetworkLoadBalancerBackendSetArray{ NetworkLoadBalancerBackendSetArgs{...} }
type NetworkLoadBalancerBackendSetArrayInput interface {
	pulumi.Input

	ToNetworkLoadBalancerBackendSetArrayOutput() NetworkLoadBalancerBackendSetArrayOutput
	ToNetworkLoadBalancerBackendSetArrayOutputWithContext(context.Context) NetworkLoadBalancerBackendSetArrayOutput
}

type NetworkLoadBalancerBackendSetArray []NetworkLoadBalancerBackendSetInput

func (NetworkLoadBalancerBackendSetArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*NetworkLoadBalancerBackendSet)(nil)).Elem()
}

func (i NetworkLoadBalancerBackendSetArray) ToNetworkLoadBalancerBackendSetArrayOutput() NetworkLoadBalancerBackendSetArrayOutput {
	return i.ToNetworkLoadBalancerBackendSetArrayOutputWithContext(context.Background())
}

func (i NetworkLoadBalancerBackendSetArray) ToNetworkLoadBalancerBackendSetArrayOutputWithContext(ctx context.Context) NetworkLoadBalancerBackendSetArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NetworkLoadBalancerBackendSetArrayOutput)
}

// NetworkLoadBalancerBackendSetMapInput is an input type that accepts NetworkLoadBalancerBackendSetMap and NetworkLoadBalancerBackendSetMapOutput values.
// You can construct a concrete instance of `NetworkLoadBalancerBackendSetMapInput` via:
//
//          NetworkLoadBalancerBackendSetMap{ "key": NetworkLoadBalancerBackendSetArgs{...} }
type NetworkLoadBalancerBackendSetMapInput interface {
	pulumi.Input

	ToNetworkLoadBalancerBackendSetMapOutput() NetworkLoadBalancerBackendSetMapOutput
	ToNetworkLoadBalancerBackendSetMapOutputWithContext(context.Context) NetworkLoadBalancerBackendSetMapOutput
}

type NetworkLoadBalancerBackendSetMap map[string]NetworkLoadBalancerBackendSetInput

func (NetworkLoadBalancerBackendSetMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*NetworkLoadBalancerBackendSet)(nil)).Elem()
}

func (i NetworkLoadBalancerBackendSetMap) ToNetworkLoadBalancerBackendSetMapOutput() NetworkLoadBalancerBackendSetMapOutput {
	return i.ToNetworkLoadBalancerBackendSetMapOutputWithContext(context.Background())
}

func (i NetworkLoadBalancerBackendSetMap) ToNetworkLoadBalancerBackendSetMapOutputWithContext(ctx context.Context) NetworkLoadBalancerBackendSetMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NetworkLoadBalancerBackendSetMapOutput)
}

type NetworkLoadBalancerBackendSetOutput struct {
	*pulumi.OutputState
}

func (NetworkLoadBalancerBackendSetOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*NetworkLoadBalancerBackendSet)(nil))
}

func (o NetworkLoadBalancerBackendSetOutput) ToNetworkLoadBalancerBackendSetOutput() NetworkLoadBalancerBackendSetOutput {
	return o
}

func (o NetworkLoadBalancerBackendSetOutput) ToNetworkLoadBalancerBackendSetOutputWithContext(ctx context.Context) NetworkLoadBalancerBackendSetOutput {
	return o
}

func (o NetworkLoadBalancerBackendSetOutput) ToNetworkLoadBalancerBackendSetPtrOutput() NetworkLoadBalancerBackendSetPtrOutput {
	return o.ToNetworkLoadBalancerBackendSetPtrOutputWithContext(context.Background())
}

func (o NetworkLoadBalancerBackendSetOutput) ToNetworkLoadBalancerBackendSetPtrOutputWithContext(ctx context.Context) NetworkLoadBalancerBackendSetPtrOutput {
	return o.ApplyT(func(v NetworkLoadBalancerBackendSet) *NetworkLoadBalancerBackendSet {
		return &v
	}).(NetworkLoadBalancerBackendSetPtrOutput)
}

type NetworkLoadBalancerBackendSetPtrOutput struct {
	*pulumi.OutputState
}

func (NetworkLoadBalancerBackendSetPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**NetworkLoadBalancerBackendSet)(nil))
}

func (o NetworkLoadBalancerBackendSetPtrOutput) ToNetworkLoadBalancerBackendSetPtrOutput() NetworkLoadBalancerBackendSetPtrOutput {
	return o
}

func (o NetworkLoadBalancerBackendSetPtrOutput) ToNetworkLoadBalancerBackendSetPtrOutputWithContext(ctx context.Context) NetworkLoadBalancerBackendSetPtrOutput {
	return o
}

type NetworkLoadBalancerBackendSetArrayOutput struct{ *pulumi.OutputState }

func (NetworkLoadBalancerBackendSetArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]NetworkLoadBalancerBackendSet)(nil))
}

func (o NetworkLoadBalancerBackendSetArrayOutput) ToNetworkLoadBalancerBackendSetArrayOutput() NetworkLoadBalancerBackendSetArrayOutput {
	return o
}

func (o NetworkLoadBalancerBackendSetArrayOutput) ToNetworkLoadBalancerBackendSetArrayOutputWithContext(ctx context.Context) NetworkLoadBalancerBackendSetArrayOutput {
	return o
}

func (o NetworkLoadBalancerBackendSetArrayOutput) Index(i pulumi.IntInput) NetworkLoadBalancerBackendSetOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) NetworkLoadBalancerBackendSet {
		return vs[0].([]NetworkLoadBalancerBackendSet)[vs[1].(int)]
	}).(NetworkLoadBalancerBackendSetOutput)
}

type NetworkLoadBalancerBackendSetMapOutput struct{ *pulumi.OutputState }

func (NetworkLoadBalancerBackendSetMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]NetworkLoadBalancerBackendSet)(nil))
}

func (o NetworkLoadBalancerBackendSetMapOutput) ToNetworkLoadBalancerBackendSetMapOutput() NetworkLoadBalancerBackendSetMapOutput {
	return o
}

func (o NetworkLoadBalancerBackendSetMapOutput) ToNetworkLoadBalancerBackendSetMapOutputWithContext(ctx context.Context) NetworkLoadBalancerBackendSetMapOutput {
	return o
}

func (o NetworkLoadBalancerBackendSetMapOutput) MapIndex(k pulumi.StringInput) NetworkLoadBalancerBackendSetOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) NetworkLoadBalancerBackendSet {
		return vs[0].(map[string]NetworkLoadBalancerBackendSet)[vs[1].(string)]
	}).(NetworkLoadBalancerBackendSetOutput)
}

func init() {
	pulumi.RegisterOutputType(NetworkLoadBalancerBackendSetOutput{})
	pulumi.RegisterOutputType(NetworkLoadBalancerBackendSetPtrOutput{})
	pulumi.RegisterOutputType(NetworkLoadBalancerBackendSetArrayOutput{})
	pulumi.RegisterOutputType(NetworkLoadBalancerBackendSetMapOutput{})
}
