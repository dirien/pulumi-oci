// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Namespace resource in Oracle Cloud Infrastructure Log Analytics service.
//
// Onboards a tenancy with Log Analytics or Offboards a tenancy from Log Analytics functionality.
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
// 		_, err := oci.NewLogAnalyticsNamespace(ctx, "testNamespace", &oci.LogAnalyticsNamespaceArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			IsOnboarded:   pulumi.Any(_var.Is_onboarded),
// 			Namespace:     pulumi.Any(_var.Namespace_namespace),
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
// Namespace can be imported using the `namespace`, e.g.
//
// ```sh
//  $ pulumi import oci:index/logAnalyticsNamespace:LogAnalyticsNamespace test_namespace "namespace"
// ```
type LogAnalyticsNamespace struct {
	pulumi.CustomResourceState

	// The OCID of the root compartment i.e. OCID of the tenancy.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Use `true` if tenancy is to be onboarded to logging analytics and `false` if tenancy is to be offboarded
	IsOnboarded pulumi.BoolOutput `pulumi:"isOnboarded"`
	// The Log Analytics namespace used for the request.
	Namespace pulumi.StringOutput `pulumi:"namespace"`
}

// NewLogAnalyticsNamespace registers a new resource with the given unique name, arguments, and options.
func NewLogAnalyticsNamespace(ctx *pulumi.Context,
	name string, args *LogAnalyticsNamespaceArgs, opts ...pulumi.ResourceOption) (*LogAnalyticsNamespace, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.IsOnboarded == nil {
		return nil, errors.New("invalid value for required argument 'IsOnboarded'")
	}
	if args.Namespace == nil {
		return nil, errors.New("invalid value for required argument 'Namespace'")
	}
	var resource LogAnalyticsNamespace
	err := ctx.RegisterResource("oci:index/logAnalyticsNamespace:LogAnalyticsNamespace", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLogAnalyticsNamespace gets an existing LogAnalyticsNamespace resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLogAnalyticsNamespace(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LogAnalyticsNamespaceState, opts ...pulumi.ResourceOption) (*LogAnalyticsNamespace, error) {
	var resource LogAnalyticsNamespace
	err := ctx.ReadResource("oci:index/logAnalyticsNamespace:LogAnalyticsNamespace", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LogAnalyticsNamespace resources.
type logAnalyticsNamespaceState struct {
	// The OCID of the root compartment i.e. OCID of the tenancy.
	CompartmentId *string `pulumi:"compartmentId"`
	// Use `true` if tenancy is to be onboarded to logging analytics and `false` if tenancy is to be offboarded
	IsOnboarded *bool `pulumi:"isOnboarded"`
	// The Log Analytics namespace used for the request.
	Namespace *string `pulumi:"namespace"`
}

type LogAnalyticsNamespaceState struct {
	// The OCID of the root compartment i.e. OCID of the tenancy.
	CompartmentId pulumi.StringPtrInput
	// Use `true` if tenancy is to be onboarded to logging analytics and `false` if tenancy is to be offboarded
	IsOnboarded pulumi.BoolPtrInput
	// The Log Analytics namespace used for the request.
	Namespace pulumi.StringPtrInput
}

func (LogAnalyticsNamespaceState) ElementType() reflect.Type {
	return reflect.TypeOf((*logAnalyticsNamespaceState)(nil)).Elem()
}

type logAnalyticsNamespaceArgs struct {
	// The OCID of the root compartment i.e. OCID of the tenancy.
	CompartmentId string `pulumi:"compartmentId"`
	// Use `true` if tenancy is to be onboarded to logging analytics and `false` if tenancy is to be offboarded
	IsOnboarded bool `pulumi:"isOnboarded"`
	// The Log Analytics namespace used for the request.
	Namespace string `pulumi:"namespace"`
}

// The set of arguments for constructing a LogAnalyticsNamespace resource.
type LogAnalyticsNamespaceArgs struct {
	// The OCID of the root compartment i.e. OCID of the tenancy.
	CompartmentId pulumi.StringInput
	// Use `true` if tenancy is to be onboarded to logging analytics and `false` if tenancy is to be offboarded
	IsOnboarded pulumi.BoolInput
	// The Log Analytics namespace used for the request.
	Namespace pulumi.StringInput
}

func (LogAnalyticsNamespaceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*logAnalyticsNamespaceArgs)(nil)).Elem()
}

type LogAnalyticsNamespaceInput interface {
	pulumi.Input

	ToLogAnalyticsNamespaceOutput() LogAnalyticsNamespaceOutput
	ToLogAnalyticsNamespaceOutputWithContext(ctx context.Context) LogAnalyticsNamespaceOutput
}

func (*LogAnalyticsNamespace) ElementType() reflect.Type {
	return reflect.TypeOf((*LogAnalyticsNamespace)(nil))
}

func (i *LogAnalyticsNamespace) ToLogAnalyticsNamespaceOutput() LogAnalyticsNamespaceOutput {
	return i.ToLogAnalyticsNamespaceOutputWithContext(context.Background())
}

func (i *LogAnalyticsNamespace) ToLogAnalyticsNamespaceOutputWithContext(ctx context.Context) LogAnalyticsNamespaceOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsNamespaceOutput)
}

func (i *LogAnalyticsNamespace) ToLogAnalyticsNamespacePtrOutput() LogAnalyticsNamespacePtrOutput {
	return i.ToLogAnalyticsNamespacePtrOutputWithContext(context.Background())
}

func (i *LogAnalyticsNamespace) ToLogAnalyticsNamespacePtrOutputWithContext(ctx context.Context) LogAnalyticsNamespacePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsNamespacePtrOutput)
}

type LogAnalyticsNamespacePtrInput interface {
	pulumi.Input

	ToLogAnalyticsNamespacePtrOutput() LogAnalyticsNamespacePtrOutput
	ToLogAnalyticsNamespacePtrOutputWithContext(ctx context.Context) LogAnalyticsNamespacePtrOutput
}

type logAnalyticsNamespacePtrType LogAnalyticsNamespaceArgs

func (*logAnalyticsNamespacePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**LogAnalyticsNamespace)(nil))
}

func (i *logAnalyticsNamespacePtrType) ToLogAnalyticsNamespacePtrOutput() LogAnalyticsNamespacePtrOutput {
	return i.ToLogAnalyticsNamespacePtrOutputWithContext(context.Background())
}

func (i *logAnalyticsNamespacePtrType) ToLogAnalyticsNamespacePtrOutputWithContext(ctx context.Context) LogAnalyticsNamespacePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsNamespacePtrOutput)
}

// LogAnalyticsNamespaceArrayInput is an input type that accepts LogAnalyticsNamespaceArray and LogAnalyticsNamespaceArrayOutput values.
// You can construct a concrete instance of `LogAnalyticsNamespaceArrayInput` via:
//
//          LogAnalyticsNamespaceArray{ LogAnalyticsNamespaceArgs{...} }
type LogAnalyticsNamespaceArrayInput interface {
	pulumi.Input

	ToLogAnalyticsNamespaceArrayOutput() LogAnalyticsNamespaceArrayOutput
	ToLogAnalyticsNamespaceArrayOutputWithContext(context.Context) LogAnalyticsNamespaceArrayOutput
}

type LogAnalyticsNamespaceArray []LogAnalyticsNamespaceInput

func (LogAnalyticsNamespaceArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LogAnalyticsNamespace)(nil)).Elem()
}

func (i LogAnalyticsNamespaceArray) ToLogAnalyticsNamespaceArrayOutput() LogAnalyticsNamespaceArrayOutput {
	return i.ToLogAnalyticsNamespaceArrayOutputWithContext(context.Background())
}

func (i LogAnalyticsNamespaceArray) ToLogAnalyticsNamespaceArrayOutputWithContext(ctx context.Context) LogAnalyticsNamespaceArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsNamespaceArrayOutput)
}

// LogAnalyticsNamespaceMapInput is an input type that accepts LogAnalyticsNamespaceMap and LogAnalyticsNamespaceMapOutput values.
// You can construct a concrete instance of `LogAnalyticsNamespaceMapInput` via:
//
//          LogAnalyticsNamespaceMap{ "key": LogAnalyticsNamespaceArgs{...} }
type LogAnalyticsNamespaceMapInput interface {
	pulumi.Input

	ToLogAnalyticsNamespaceMapOutput() LogAnalyticsNamespaceMapOutput
	ToLogAnalyticsNamespaceMapOutputWithContext(context.Context) LogAnalyticsNamespaceMapOutput
}

type LogAnalyticsNamespaceMap map[string]LogAnalyticsNamespaceInput

func (LogAnalyticsNamespaceMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LogAnalyticsNamespace)(nil)).Elem()
}

func (i LogAnalyticsNamespaceMap) ToLogAnalyticsNamespaceMapOutput() LogAnalyticsNamespaceMapOutput {
	return i.ToLogAnalyticsNamespaceMapOutputWithContext(context.Background())
}

func (i LogAnalyticsNamespaceMap) ToLogAnalyticsNamespaceMapOutputWithContext(ctx context.Context) LogAnalyticsNamespaceMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LogAnalyticsNamespaceMapOutput)
}

type LogAnalyticsNamespaceOutput struct {
	*pulumi.OutputState
}

func (LogAnalyticsNamespaceOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LogAnalyticsNamespace)(nil))
}

func (o LogAnalyticsNamespaceOutput) ToLogAnalyticsNamespaceOutput() LogAnalyticsNamespaceOutput {
	return o
}

func (o LogAnalyticsNamespaceOutput) ToLogAnalyticsNamespaceOutputWithContext(ctx context.Context) LogAnalyticsNamespaceOutput {
	return o
}

func (o LogAnalyticsNamespaceOutput) ToLogAnalyticsNamespacePtrOutput() LogAnalyticsNamespacePtrOutput {
	return o.ToLogAnalyticsNamespacePtrOutputWithContext(context.Background())
}

func (o LogAnalyticsNamespaceOutput) ToLogAnalyticsNamespacePtrOutputWithContext(ctx context.Context) LogAnalyticsNamespacePtrOutput {
	return o.ApplyT(func(v LogAnalyticsNamespace) *LogAnalyticsNamespace {
		return &v
	}).(LogAnalyticsNamespacePtrOutput)
}

type LogAnalyticsNamespacePtrOutput struct {
	*pulumi.OutputState
}

func (LogAnalyticsNamespacePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**LogAnalyticsNamespace)(nil))
}

func (o LogAnalyticsNamespacePtrOutput) ToLogAnalyticsNamespacePtrOutput() LogAnalyticsNamespacePtrOutput {
	return o
}

func (o LogAnalyticsNamespacePtrOutput) ToLogAnalyticsNamespacePtrOutputWithContext(ctx context.Context) LogAnalyticsNamespacePtrOutput {
	return o
}

type LogAnalyticsNamespaceArrayOutput struct{ *pulumi.OutputState }

func (LogAnalyticsNamespaceArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]LogAnalyticsNamespace)(nil))
}

func (o LogAnalyticsNamespaceArrayOutput) ToLogAnalyticsNamespaceArrayOutput() LogAnalyticsNamespaceArrayOutput {
	return o
}

func (o LogAnalyticsNamespaceArrayOutput) ToLogAnalyticsNamespaceArrayOutputWithContext(ctx context.Context) LogAnalyticsNamespaceArrayOutput {
	return o
}

func (o LogAnalyticsNamespaceArrayOutput) Index(i pulumi.IntInput) LogAnalyticsNamespaceOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) LogAnalyticsNamespace {
		return vs[0].([]LogAnalyticsNamespace)[vs[1].(int)]
	}).(LogAnalyticsNamespaceOutput)
}

type LogAnalyticsNamespaceMapOutput struct{ *pulumi.OutputState }

func (LogAnalyticsNamespaceMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]LogAnalyticsNamespace)(nil))
}

func (o LogAnalyticsNamespaceMapOutput) ToLogAnalyticsNamespaceMapOutput() LogAnalyticsNamespaceMapOutput {
	return o
}

func (o LogAnalyticsNamespaceMapOutput) ToLogAnalyticsNamespaceMapOutputWithContext(ctx context.Context) LogAnalyticsNamespaceMapOutput {
	return o
}

func (o LogAnalyticsNamespaceMapOutput) MapIndex(k pulumi.StringInput) LogAnalyticsNamespaceOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) LogAnalyticsNamespace {
		return vs[0].(map[string]LogAnalyticsNamespace)[vs[1].(string)]
	}).(LogAnalyticsNamespaceOutput)
}

func init() {
	pulumi.RegisterOutputType(LogAnalyticsNamespaceOutput{})
	pulumi.RegisterOutputType(LogAnalyticsNamespacePtrOutput{})
	pulumi.RegisterOutputType(LogAnalyticsNamespaceArrayOutput{})
	pulumi.RegisterOutputType(LogAnalyticsNamespaceMapOutput{})
}