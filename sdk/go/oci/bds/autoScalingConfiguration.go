// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package bds

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Auto Scaling Configuration resource in Oracle Cloud Infrastructure Big Data Service service.
//
// Add an autoscale configuration to the cluster.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/bds"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := bds.NewAutoScalingConfiguration(ctx, "testAutoScalingConfiguration", &bds.AutoScalingConfigurationArgs{
// 			BdsInstanceId:        pulumi.Any(oci_bds_bds_instance.Test_bds_instance.Id),
// 			ClusterAdminPassword: pulumi.Any(_var.Auto_scaling_configuration_cluster_admin_password),
// 			IsEnabled:            pulumi.Any(_var.Auto_scaling_configuration_is_enabled),
// 			NodeType:             pulumi.Any(_var.Auto_scaling_configuration_node_type),
// 			Policy: &bds.AutoScalingConfigurationPolicyArgs{
// 				PolicyType: pulumi.Any(_var.Auto_scaling_configuration_policy_policy_type),
// 				Rules: bds.AutoScalingConfigurationPolicyRuleArray{
// 					&bds.AutoScalingConfigurationPolicyRuleArgs{
// 						Action: pulumi.Any(_var.Auto_scaling_configuration_policy_rules_action),
// 						Metric: &bds.AutoScalingConfigurationPolicyRuleMetricArgs{
// 							MetricType: pulumi.Any(_var.Auto_scaling_configuration_policy_rules_metric_metric_type),
// 							Threshold: &bds.AutoScalingConfigurationPolicyRuleMetricThresholdArgs{
// 								DurationInMinutes: pulumi.Any(_var.Auto_scaling_configuration_policy_rules_metric_threshold_duration_in_minutes),
// 								Operator:          pulumi.Any(_var.Auto_scaling_configuration_policy_rules_metric_threshold_operator),
// 								Value:             pulumi.Any(_var.Auto_scaling_configuration_policy_rules_metric_threshold_value),
// 							},
// 						},
// 					},
// 				},
// 			},
// 			DisplayName: pulumi.Any(_var.Auto_scaling_configuration_display_name),
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
// AutoScalingConfiguration can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:bds/autoScalingConfiguration:AutoScalingConfiguration test_auto_scaling_configuration "bdsInstances/{bdsInstanceId}/autoScalingConfiguration/{autoScalingConfigurationId}"
// ```
type AutoScalingConfiguration struct {
	pulumi.CustomResourceState

	// The OCID of the cluster.
	BdsInstanceId pulumi.StringOutput `pulumi:"bdsInstanceId"`
	// (Updatable) Base-64 encoded password for the cluster (and Cloudera Manager) admin user.
	ClusterAdminPassword pulumi.StringOutput `pulumi:"clusterAdminPassword"`
	// (Updatable) A user-friendly name. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Whether the autoscale configuration is enabled.
	IsEnabled pulumi.BoolOutput `pulumi:"isEnabled"`
	// A node type that is managed by an autoscale configuration. The only supported type is WORKER.
	NodeType pulumi.StringOutput `pulumi:"nodeType"`
	// (Updatable) Policy definitions for the autoscale configuration.
	Policy AutoScalingConfigurationPolicyOutput `pulumi:"policy"`
	// The state of the autoscale configuration.
	State pulumi.StringOutput `pulumi:"state"`
	// The time the cluster was created, shown as an RFC 3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the autoscale configuration was updated, shown as an RFC 3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewAutoScalingConfiguration registers a new resource with the given unique name, arguments, and options.
func NewAutoScalingConfiguration(ctx *pulumi.Context,
	name string, args *AutoScalingConfigurationArgs, opts ...pulumi.ResourceOption) (*AutoScalingConfiguration, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.BdsInstanceId == nil {
		return nil, errors.New("invalid value for required argument 'BdsInstanceId'")
	}
	if args.ClusterAdminPassword == nil {
		return nil, errors.New("invalid value for required argument 'ClusterAdminPassword'")
	}
	if args.IsEnabled == nil {
		return nil, errors.New("invalid value for required argument 'IsEnabled'")
	}
	if args.NodeType == nil {
		return nil, errors.New("invalid value for required argument 'NodeType'")
	}
	if args.Policy == nil {
		return nil, errors.New("invalid value for required argument 'Policy'")
	}
	var resource AutoScalingConfiguration
	err := ctx.RegisterResource("oci:bds/autoScalingConfiguration:AutoScalingConfiguration", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAutoScalingConfiguration gets an existing AutoScalingConfiguration resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAutoScalingConfiguration(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AutoScalingConfigurationState, opts ...pulumi.ResourceOption) (*AutoScalingConfiguration, error) {
	var resource AutoScalingConfiguration
	err := ctx.ReadResource("oci:bds/autoScalingConfiguration:AutoScalingConfiguration", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering AutoScalingConfiguration resources.
type autoScalingConfigurationState struct {
	// The OCID of the cluster.
	BdsInstanceId *string `pulumi:"bdsInstanceId"`
	// (Updatable) Base-64 encoded password for the cluster (and Cloudera Manager) admin user.
	ClusterAdminPassword *string `pulumi:"clusterAdminPassword"`
	// (Updatable) A user-friendly name. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Whether the autoscale configuration is enabled.
	IsEnabled *bool `pulumi:"isEnabled"`
	// A node type that is managed by an autoscale configuration. The only supported type is WORKER.
	NodeType *string `pulumi:"nodeType"`
	// (Updatable) Policy definitions for the autoscale configuration.
	Policy *AutoScalingConfigurationPolicy `pulumi:"policy"`
	// The state of the autoscale configuration.
	State *string `pulumi:"state"`
	// The time the cluster was created, shown as an RFC 3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the autoscale configuration was updated, shown as an RFC 3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type AutoScalingConfigurationState struct {
	// The OCID of the cluster.
	BdsInstanceId pulumi.StringPtrInput
	// (Updatable) Base-64 encoded password for the cluster (and Cloudera Manager) admin user.
	ClusterAdminPassword pulumi.StringPtrInput
	// (Updatable) A user-friendly name. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Whether the autoscale configuration is enabled.
	IsEnabled pulumi.BoolPtrInput
	// A node type that is managed by an autoscale configuration. The only supported type is WORKER.
	NodeType pulumi.StringPtrInput
	// (Updatable) Policy definitions for the autoscale configuration.
	Policy AutoScalingConfigurationPolicyPtrInput
	// The state of the autoscale configuration.
	State pulumi.StringPtrInput
	// The time the cluster was created, shown as an RFC 3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time the autoscale configuration was updated, shown as an RFC 3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (AutoScalingConfigurationState) ElementType() reflect.Type {
	return reflect.TypeOf((*autoScalingConfigurationState)(nil)).Elem()
}

type autoScalingConfigurationArgs struct {
	// The OCID of the cluster.
	BdsInstanceId string `pulumi:"bdsInstanceId"`
	// (Updatable) Base-64 encoded password for the cluster (and Cloudera Manager) admin user.
	ClusterAdminPassword string `pulumi:"clusterAdminPassword"`
	// (Updatable) A user-friendly name. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Whether the autoscale configuration is enabled.
	IsEnabled bool `pulumi:"isEnabled"`
	// A node type that is managed by an autoscale configuration. The only supported type is WORKER.
	NodeType string `pulumi:"nodeType"`
	// (Updatable) Policy definitions for the autoscale configuration.
	Policy AutoScalingConfigurationPolicy `pulumi:"policy"`
}

// The set of arguments for constructing a AutoScalingConfiguration resource.
type AutoScalingConfigurationArgs struct {
	// The OCID of the cluster.
	BdsInstanceId pulumi.StringInput
	// (Updatable) Base-64 encoded password for the cluster (and Cloudera Manager) admin user.
	ClusterAdminPassword pulumi.StringInput
	// (Updatable) A user-friendly name. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Whether the autoscale configuration is enabled.
	IsEnabled pulumi.BoolInput
	// A node type that is managed by an autoscale configuration. The only supported type is WORKER.
	NodeType pulumi.StringInput
	// (Updatable) Policy definitions for the autoscale configuration.
	Policy AutoScalingConfigurationPolicyInput
}

func (AutoScalingConfigurationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*autoScalingConfigurationArgs)(nil)).Elem()
}

type AutoScalingConfigurationInput interface {
	pulumi.Input

	ToAutoScalingConfigurationOutput() AutoScalingConfigurationOutput
	ToAutoScalingConfigurationOutputWithContext(ctx context.Context) AutoScalingConfigurationOutput
}

func (*AutoScalingConfiguration) ElementType() reflect.Type {
	return reflect.TypeOf((*AutoScalingConfiguration)(nil))
}

func (i *AutoScalingConfiguration) ToAutoScalingConfigurationOutput() AutoScalingConfigurationOutput {
	return i.ToAutoScalingConfigurationOutputWithContext(context.Background())
}

func (i *AutoScalingConfiguration) ToAutoScalingConfigurationOutputWithContext(ctx context.Context) AutoScalingConfigurationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutoScalingConfigurationOutput)
}

func (i *AutoScalingConfiguration) ToAutoScalingConfigurationPtrOutput() AutoScalingConfigurationPtrOutput {
	return i.ToAutoScalingConfigurationPtrOutputWithContext(context.Background())
}

func (i *AutoScalingConfiguration) ToAutoScalingConfigurationPtrOutputWithContext(ctx context.Context) AutoScalingConfigurationPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutoScalingConfigurationPtrOutput)
}

type AutoScalingConfigurationPtrInput interface {
	pulumi.Input

	ToAutoScalingConfigurationPtrOutput() AutoScalingConfigurationPtrOutput
	ToAutoScalingConfigurationPtrOutputWithContext(ctx context.Context) AutoScalingConfigurationPtrOutput
}

type autoScalingConfigurationPtrType AutoScalingConfigurationArgs

func (*autoScalingConfigurationPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**AutoScalingConfiguration)(nil))
}

func (i *autoScalingConfigurationPtrType) ToAutoScalingConfigurationPtrOutput() AutoScalingConfigurationPtrOutput {
	return i.ToAutoScalingConfigurationPtrOutputWithContext(context.Background())
}

func (i *autoScalingConfigurationPtrType) ToAutoScalingConfigurationPtrOutputWithContext(ctx context.Context) AutoScalingConfigurationPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutoScalingConfigurationPtrOutput)
}

// AutoScalingConfigurationArrayInput is an input type that accepts AutoScalingConfigurationArray and AutoScalingConfigurationArrayOutput values.
// You can construct a concrete instance of `AutoScalingConfigurationArrayInput` via:
//
//          AutoScalingConfigurationArray{ AutoScalingConfigurationArgs{...} }
type AutoScalingConfigurationArrayInput interface {
	pulumi.Input

	ToAutoScalingConfigurationArrayOutput() AutoScalingConfigurationArrayOutput
	ToAutoScalingConfigurationArrayOutputWithContext(context.Context) AutoScalingConfigurationArrayOutput
}

type AutoScalingConfigurationArray []AutoScalingConfigurationInput

func (AutoScalingConfigurationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AutoScalingConfiguration)(nil)).Elem()
}

func (i AutoScalingConfigurationArray) ToAutoScalingConfigurationArrayOutput() AutoScalingConfigurationArrayOutput {
	return i.ToAutoScalingConfigurationArrayOutputWithContext(context.Background())
}

func (i AutoScalingConfigurationArray) ToAutoScalingConfigurationArrayOutputWithContext(ctx context.Context) AutoScalingConfigurationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutoScalingConfigurationArrayOutput)
}

// AutoScalingConfigurationMapInput is an input type that accepts AutoScalingConfigurationMap and AutoScalingConfigurationMapOutput values.
// You can construct a concrete instance of `AutoScalingConfigurationMapInput` via:
//
//          AutoScalingConfigurationMap{ "key": AutoScalingConfigurationArgs{...} }
type AutoScalingConfigurationMapInput interface {
	pulumi.Input

	ToAutoScalingConfigurationMapOutput() AutoScalingConfigurationMapOutput
	ToAutoScalingConfigurationMapOutputWithContext(context.Context) AutoScalingConfigurationMapOutput
}

type AutoScalingConfigurationMap map[string]AutoScalingConfigurationInput

func (AutoScalingConfigurationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AutoScalingConfiguration)(nil)).Elem()
}

func (i AutoScalingConfigurationMap) ToAutoScalingConfigurationMapOutput() AutoScalingConfigurationMapOutput {
	return i.ToAutoScalingConfigurationMapOutputWithContext(context.Background())
}

func (i AutoScalingConfigurationMap) ToAutoScalingConfigurationMapOutputWithContext(ctx context.Context) AutoScalingConfigurationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutoScalingConfigurationMapOutput)
}

type AutoScalingConfigurationOutput struct {
	*pulumi.OutputState
}

func (AutoScalingConfigurationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*AutoScalingConfiguration)(nil))
}

func (o AutoScalingConfigurationOutput) ToAutoScalingConfigurationOutput() AutoScalingConfigurationOutput {
	return o
}

func (o AutoScalingConfigurationOutput) ToAutoScalingConfigurationOutputWithContext(ctx context.Context) AutoScalingConfigurationOutput {
	return o
}

func (o AutoScalingConfigurationOutput) ToAutoScalingConfigurationPtrOutput() AutoScalingConfigurationPtrOutput {
	return o.ToAutoScalingConfigurationPtrOutputWithContext(context.Background())
}

func (o AutoScalingConfigurationOutput) ToAutoScalingConfigurationPtrOutputWithContext(ctx context.Context) AutoScalingConfigurationPtrOutput {
	return o.ApplyT(func(v AutoScalingConfiguration) *AutoScalingConfiguration {
		return &v
	}).(AutoScalingConfigurationPtrOutput)
}

type AutoScalingConfigurationPtrOutput struct {
	*pulumi.OutputState
}

func (AutoScalingConfigurationPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**AutoScalingConfiguration)(nil))
}

func (o AutoScalingConfigurationPtrOutput) ToAutoScalingConfigurationPtrOutput() AutoScalingConfigurationPtrOutput {
	return o
}

func (o AutoScalingConfigurationPtrOutput) ToAutoScalingConfigurationPtrOutputWithContext(ctx context.Context) AutoScalingConfigurationPtrOutput {
	return o
}

type AutoScalingConfigurationArrayOutput struct{ *pulumi.OutputState }

func (AutoScalingConfigurationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]AutoScalingConfiguration)(nil))
}

func (o AutoScalingConfigurationArrayOutput) ToAutoScalingConfigurationArrayOutput() AutoScalingConfigurationArrayOutput {
	return o
}

func (o AutoScalingConfigurationArrayOutput) ToAutoScalingConfigurationArrayOutputWithContext(ctx context.Context) AutoScalingConfigurationArrayOutput {
	return o
}

func (o AutoScalingConfigurationArrayOutput) Index(i pulumi.IntInput) AutoScalingConfigurationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) AutoScalingConfiguration {
		return vs[0].([]AutoScalingConfiguration)[vs[1].(int)]
	}).(AutoScalingConfigurationOutput)
}

type AutoScalingConfigurationMapOutput struct{ *pulumi.OutputState }

func (AutoScalingConfigurationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]AutoScalingConfiguration)(nil))
}

func (o AutoScalingConfigurationMapOutput) ToAutoScalingConfigurationMapOutput() AutoScalingConfigurationMapOutput {
	return o
}

func (o AutoScalingConfigurationMapOutput) ToAutoScalingConfigurationMapOutputWithContext(ctx context.Context) AutoScalingConfigurationMapOutput {
	return o
}

func (o AutoScalingConfigurationMapOutput) MapIndex(k pulumi.StringInput) AutoScalingConfigurationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) AutoScalingConfiguration {
		return vs[0].(map[string]AutoScalingConfiguration)[vs[1].(string)]
	}).(AutoScalingConfigurationOutput)
}

func init() {
	pulumi.RegisterOutputType(AutoScalingConfigurationOutput{})
	pulumi.RegisterOutputType(AutoScalingConfigurationPtrOutput{})
	pulumi.RegisterOutputType(AutoScalingConfigurationArrayOutput{})
	pulumi.RegisterOutputType(AutoScalingConfigurationMapOutput{})
}