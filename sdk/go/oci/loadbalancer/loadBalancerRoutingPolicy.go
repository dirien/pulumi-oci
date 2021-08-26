// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package loadbalancer

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Load Balancer Routing Policy resource in Oracle Cloud Infrastructure Load Balancer service.
//
// Adds a routing policy to a load balancer. For more information, see
// [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/loadbalancer"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := loadbalancer.NewLoadBalancerRoutingPolicy(ctx, "testLoadBalancerRoutingPolicy", &loadbalancer.LoadBalancerRoutingPolicyArgs{
// 			ConditionLanguageVersion: pulumi.Any(_var.Load_balancer_routing_policy_condition_language_version),
// 			LoadBalancerId:           pulumi.Any(oci_load_balancer_load_balancer.Test_load_balancer.Id),
// 			Rules: loadbalancer.LoadBalancerRoutingPolicyRuleArray{
// 				&loadbalancer.LoadBalancerRoutingPolicyRuleArgs{
// 					Actions: loadbalancer.LoadBalancerRoutingPolicyRuleActionArray{
// 						&loadbalancer.LoadBalancerRoutingPolicyRuleActionArgs{
// 							Name:           pulumi.Any(_var.Load_balancer_routing_policy_rules_actions_name),
// 							BackendSetName: pulumi.Any(oci_load_balancer_backend_set.Test_backend_set.Name),
// 						},
// 					},
// 					Condition: pulumi.Any(_var.Load_balancer_routing_policy_rules_condition),
// 					Name:      pulumi.Any(_var.Load_balancer_routing_policy_rules_name),
// 				},
// 			},
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
// LoadBalancerRoutingPolicies can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:loadbalancer/loadBalancerRoutingPolicy:LoadBalancerRoutingPolicy test_load_balancer_routing_policy "loadBalancers/{loadBalancerId}/routingPolicies/{routingPolicyName}"
// ```
type LoadBalancerRoutingPolicy struct {
	pulumi.CustomResourceState

	// (Updatable) The version of the language in which `condition` of `rules` are composed.
	ConditionLanguageVersion pulumi.StringOutput `pulumi:"conditionLanguageVersion"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
	LoadBalancerId pulumi.StringOutput `pulumi:"loadBalancerId"`
	// (Updatable) A unique name for the routing policy rule. Avoid entering confidential information.
	Name pulumi.StringOutput `pulumi:"name"`
	// (Updatable) The list of routing rules.
	Rules LoadBalancerRoutingPolicyRuleArrayOutput `pulumi:"rules"`
	State pulumi.StringOutput                      `pulumi:"state"`
}

// NewLoadBalancerRoutingPolicy registers a new resource with the given unique name, arguments, and options.
func NewLoadBalancerRoutingPolicy(ctx *pulumi.Context,
	name string, args *LoadBalancerRoutingPolicyArgs, opts ...pulumi.ResourceOption) (*LoadBalancerRoutingPolicy, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ConditionLanguageVersion == nil {
		return nil, errors.New("invalid value for required argument 'ConditionLanguageVersion'")
	}
	if args.LoadBalancerId == nil {
		return nil, errors.New("invalid value for required argument 'LoadBalancerId'")
	}
	if args.Rules == nil {
		return nil, errors.New("invalid value for required argument 'Rules'")
	}
	var resource LoadBalancerRoutingPolicy
	err := ctx.RegisterResource("oci:loadbalancer/loadBalancerRoutingPolicy:LoadBalancerRoutingPolicy", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLoadBalancerRoutingPolicy gets an existing LoadBalancerRoutingPolicy resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLoadBalancerRoutingPolicy(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LoadBalancerRoutingPolicyState, opts ...pulumi.ResourceOption) (*LoadBalancerRoutingPolicy, error) {
	var resource LoadBalancerRoutingPolicy
	err := ctx.ReadResource("oci:loadbalancer/loadBalancerRoutingPolicy:LoadBalancerRoutingPolicy", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LoadBalancerRoutingPolicy resources.
type loadBalancerRoutingPolicyState struct {
	// (Updatable) The version of the language in which `condition` of `rules` are composed.
	ConditionLanguageVersion *string `pulumi:"conditionLanguageVersion"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
	LoadBalancerId *string `pulumi:"loadBalancerId"`
	// (Updatable) A unique name for the routing policy rule. Avoid entering confidential information.
	Name *string `pulumi:"name"`
	// (Updatable) The list of routing rules.
	Rules []LoadBalancerRoutingPolicyRule `pulumi:"rules"`
	State *string                         `pulumi:"state"`
}

type LoadBalancerRoutingPolicyState struct {
	// (Updatable) The version of the language in which `condition` of `rules` are composed.
	ConditionLanguageVersion pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
	LoadBalancerId pulumi.StringPtrInput
	// (Updatable) A unique name for the routing policy rule. Avoid entering confidential information.
	Name pulumi.StringPtrInput
	// (Updatable) The list of routing rules.
	Rules LoadBalancerRoutingPolicyRuleArrayInput
	State pulumi.StringPtrInput
}

func (LoadBalancerRoutingPolicyState) ElementType() reflect.Type {
	return reflect.TypeOf((*loadBalancerRoutingPolicyState)(nil)).Elem()
}

type loadBalancerRoutingPolicyArgs struct {
	// (Updatable) The version of the language in which `condition` of `rules` are composed.
	ConditionLanguageVersion string `pulumi:"conditionLanguageVersion"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
	LoadBalancerId string `pulumi:"loadBalancerId"`
	// (Updatable) A unique name for the routing policy rule. Avoid entering confidential information.
	Name *string `pulumi:"name"`
	// (Updatable) The list of routing rules.
	Rules []LoadBalancerRoutingPolicyRule `pulumi:"rules"`
}

// The set of arguments for constructing a LoadBalancerRoutingPolicy resource.
type LoadBalancerRoutingPolicyArgs struct {
	// (Updatable) The version of the language in which `condition` of `rules` are composed.
	ConditionLanguageVersion pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
	LoadBalancerId pulumi.StringInput
	// (Updatable) A unique name for the routing policy rule. Avoid entering confidential information.
	Name pulumi.StringPtrInput
	// (Updatable) The list of routing rules.
	Rules LoadBalancerRoutingPolicyRuleArrayInput
}

func (LoadBalancerRoutingPolicyArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*loadBalancerRoutingPolicyArgs)(nil)).Elem()
}

type LoadBalancerRoutingPolicyInput interface {
	pulumi.Input

	ToLoadBalancerRoutingPolicyOutput() LoadBalancerRoutingPolicyOutput
	ToLoadBalancerRoutingPolicyOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyOutput
}

func (*LoadBalancerRoutingPolicy) ElementType() reflect.Type {
	return reflect.TypeOf((*LoadBalancerRoutingPolicy)(nil))
}

func (i *LoadBalancerRoutingPolicy) ToLoadBalancerRoutingPolicyOutput() LoadBalancerRoutingPolicyOutput {
	return i.ToLoadBalancerRoutingPolicyOutputWithContext(context.Background())
}

func (i *LoadBalancerRoutingPolicy) ToLoadBalancerRoutingPolicyOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerRoutingPolicyOutput)
}

func (i *LoadBalancerRoutingPolicy) ToLoadBalancerRoutingPolicyPtrOutput() LoadBalancerRoutingPolicyPtrOutput {
	return i.ToLoadBalancerRoutingPolicyPtrOutputWithContext(context.Background())
}

func (i *LoadBalancerRoutingPolicy) ToLoadBalancerRoutingPolicyPtrOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerRoutingPolicyPtrOutput)
}

type LoadBalancerRoutingPolicyPtrInput interface {
	pulumi.Input

	ToLoadBalancerRoutingPolicyPtrOutput() LoadBalancerRoutingPolicyPtrOutput
	ToLoadBalancerRoutingPolicyPtrOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyPtrOutput
}

type loadBalancerRoutingPolicyPtrType LoadBalancerRoutingPolicyArgs

func (*loadBalancerRoutingPolicyPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**LoadBalancerRoutingPolicy)(nil))
}

func (i *loadBalancerRoutingPolicyPtrType) ToLoadBalancerRoutingPolicyPtrOutput() LoadBalancerRoutingPolicyPtrOutput {
	return i.ToLoadBalancerRoutingPolicyPtrOutputWithContext(context.Background())
}

func (i *loadBalancerRoutingPolicyPtrType) ToLoadBalancerRoutingPolicyPtrOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerRoutingPolicyPtrOutput)
}

// LoadBalancerRoutingPolicyArrayInput is an input type that accepts LoadBalancerRoutingPolicyArray and LoadBalancerRoutingPolicyArrayOutput values.
// You can construct a concrete instance of `LoadBalancerRoutingPolicyArrayInput` via:
//
//          LoadBalancerRoutingPolicyArray{ LoadBalancerRoutingPolicyArgs{...} }
type LoadBalancerRoutingPolicyArrayInput interface {
	pulumi.Input

	ToLoadBalancerRoutingPolicyArrayOutput() LoadBalancerRoutingPolicyArrayOutput
	ToLoadBalancerRoutingPolicyArrayOutputWithContext(context.Context) LoadBalancerRoutingPolicyArrayOutput
}

type LoadBalancerRoutingPolicyArray []LoadBalancerRoutingPolicyInput

func (LoadBalancerRoutingPolicyArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LoadBalancerRoutingPolicy)(nil)).Elem()
}

func (i LoadBalancerRoutingPolicyArray) ToLoadBalancerRoutingPolicyArrayOutput() LoadBalancerRoutingPolicyArrayOutput {
	return i.ToLoadBalancerRoutingPolicyArrayOutputWithContext(context.Background())
}

func (i LoadBalancerRoutingPolicyArray) ToLoadBalancerRoutingPolicyArrayOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerRoutingPolicyArrayOutput)
}

// LoadBalancerRoutingPolicyMapInput is an input type that accepts LoadBalancerRoutingPolicyMap and LoadBalancerRoutingPolicyMapOutput values.
// You can construct a concrete instance of `LoadBalancerRoutingPolicyMapInput` via:
//
//          LoadBalancerRoutingPolicyMap{ "key": LoadBalancerRoutingPolicyArgs{...} }
type LoadBalancerRoutingPolicyMapInput interface {
	pulumi.Input

	ToLoadBalancerRoutingPolicyMapOutput() LoadBalancerRoutingPolicyMapOutput
	ToLoadBalancerRoutingPolicyMapOutputWithContext(context.Context) LoadBalancerRoutingPolicyMapOutput
}

type LoadBalancerRoutingPolicyMap map[string]LoadBalancerRoutingPolicyInput

func (LoadBalancerRoutingPolicyMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LoadBalancerRoutingPolicy)(nil)).Elem()
}

func (i LoadBalancerRoutingPolicyMap) ToLoadBalancerRoutingPolicyMapOutput() LoadBalancerRoutingPolicyMapOutput {
	return i.ToLoadBalancerRoutingPolicyMapOutputWithContext(context.Background())
}

func (i LoadBalancerRoutingPolicyMap) ToLoadBalancerRoutingPolicyMapOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerRoutingPolicyMapOutput)
}

type LoadBalancerRoutingPolicyOutput struct {
	*pulumi.OutputState
}

func (LoadBalancerRoutingPolicyOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LoadBalancerRoutingPolicy)(nil))
}

func (o LoadBalancerRoutingPolicyOutput) ToLoadBalancerRoutingPolicyOutput() LoadBalancerRoutingPolicyOutput {
	return o
}

func (o LoadBalancerRoutingPolicyOutput) ToLoadBalancerRoutingPolicyOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyOutput {
	return o
}

func (o LoadBalancerRoutingPolicyOutput) ToLoadBalancerRoutingPolicyPtrOutput() LoadBalancerRoutingPolicyPtrOutput {
	return o.ToLoadBalancerRoutingPolicyPtrOutputWithContext(context.Background())
}

func (o LoadBalancerRoutingPolicyOutput) ToLoadBalancerRoutingPolicyPtrOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyPtrOutput {
	return o.ApplyT(func(v LoadBalancerRoutingPolicy) *LoadBalancerRoutingPolicy {
		return &v
	}).(LoadBalancerRoutingPolicyPtrOutput)
}

type LoadBalancerRoutingPolicyPtrOutput struct {
	*pulumi.OutputState
}

func (LoadBalancerRoutingPolicyPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**LoadBalancerRoutingPolicy)(nil))
}

func (o LoadBalancerRoutingPolicyPtrOutput) ToLoadBalancerRoutingPolicyPtrOutput() LoadBalancerRoutingPolicyPtrOutput {
	return o
}

func (o LoadBalancerRoutingPolicyPtrOutput) ToLoadBalancerRoutingPolicyPtrOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyPtrOutput {
	return o
}

type LoadBalancerRoutingPolicyArrayOutput struct{ *pulumi.OutputState }

func (LoadBalancerRoutingPolicyArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]LoadBalancerRoutingPolicy)(nil))
}

func (o LoadBalancerRoutingPolicyArrayOutput) ToLoadBalancerRoutingPolicyArrayOutput() LoadBalancerRoutingPolicyArrayOutput {
	return o
}

func (o LoadBalancerRoutingPolicyArrayOutput) ToLoadBalancerRoutingPolicyArrayOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyArrayOutput {
	return o
}

func (o LoadBalancerRoutingPolicyArrayOutput) Index(i pulumi.IntInput) LoadBalancerRoutingPolicyOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) LoadBalancerRoutingPolicy {
		return vs[0].([]LoadBalancerRoutingPolicy)[vs[1].(int)]
	}).(LoadBalancerRoutingPolicyOutput)
}

type LoadBalancerRoutingPolicyMapOutput struct{ *pulumi.OutputState }

func (LoadBalancerRoutingPolicyMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]LoadBalancerRoutingPolicy)(nil))
}

func (o LoadBalancerRoutingPolicyMapOutput) ToLoadBalancerRoutingPolicyMapOutput() LoadBalancerRoutingPolicyMapOutput {
	return o
}

func (o LoadBalancerRoutingPolicyMapOutput) ToLoadBalancerRoutingPolicyMapOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyMapOutput {
	return o
}

func (o LoadBalancerRoutingPolicyMapOutput) MapIndex(k pulumi.StringInput) LoadBalancerRoutingPolicyOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) LoadBalancerRoutingPolicy {
		return vs[0].(map[string]LoadBalancerRoutingPolicy)[vs[1].(string)]
	}).(LoadBalancerRoutingPolicyOutput)
}

func init() {
	pulumi.RegisterOutputType(LoadBalancerRoutingPolicyOutput{})
	pulumi.RegisterOutputType(LoadBalancerRoutingPolicyPtrOutput{})
	pulumi.RegisterOutputType(LoadBalancerRoutingPolicyArrayOutput{})
	pulumi.RegisterOutputType(LoadBalancerRoutingPolicyMapOutput{})
}
