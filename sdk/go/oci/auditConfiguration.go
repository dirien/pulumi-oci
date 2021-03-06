// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Configuration resource in Oracle Cloud Infrastructure Audit service.
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
// 		_, err := oci.NewAuditConfiguration(ctx, "testConfiguration", &oci.AuditConfigurationArgs{
// 			CompartmentId:       pulumi.Any(_var.Tenancy_ocid),
// 			RetentionPeriodDays: pulumi.Any(_var.Configuration_retention_period_days),
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
// Import is not supported for this resource.
type AuditConfiguration struct {
	pulumi.CustomResourceState

	// ID of the root compartment (tenancy)
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
	RetentionPeriodDays pulumi.IntOutput `pulumi:"retentionPeriodDays"`
}

// NewAuditConfiguration registers a new resource with the given unique name, arguments, and options.
func NewAuditConfiguration(ctx *pulumi.Context,
	name string, args *AuditConfigurationArgs, opts ...pulumi.ResourceOption) (*AuditConfiguration, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.RetentionPeriodDays == nil {
		return nil, errors.New("invalid value for required argument 'RetentionPeriodDays'")
	}
	var resource AuditConfiguration
	err := ctx.RegisterResource("oci:index/auditConfiguration:AuditConfiguration", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAuditConfiguration gets an existing AuditConfiguration resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAuditConfiguration(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AuditConfigurationState, opts ...pulumi.ResourceOption) (*AuditConfiguration, error) {
	var resource AuditConfiguration
	err := ctx.ReadResource("oci:index/auditConfiguration:AuditConfiguration", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering AuditConfiguration resources.
type auditConfigurationState struct {
	// ID of the root compartment (tenancy)
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
	RetentionPeriodDays *int `pulumi:"retentionPeriodDays"`
}

type AuditConfigurationState struct {
	// ID of the root compartment (tenancy)
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
	RetentionPeriodDays pulumi.IntPtrInput
}

func (AuditConfigurationState) ElementType() reflect.Type {
	return reflect.TypeOf((*auditConfigurationState)(nil)).Elem()
}

type auditConfigurationArgs struct {
	// ID of the root compartment (tenancy)
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
	RetentionPeriodDays int `pulumi:"retentionPeriodDays"`
}

// The set of arguments for constructing a AuditConfiguration resource.
type AuditConfigurationArgs struct {
	// ID of the root compartment (tenancy)
	CompartmentId pulumi.StringInput
	// (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
	RetentionPeriodDays pulumi.IntInput
}

func (AuditConfigurationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*auditConfigurationArgs)(nil)).Elem()
}

type AuditConfigurationInput interface {
	pulumi.Input

	ToAuditConfigurationOutput() AuditConfigurationOutput
	ToAuditConfigurationOutputWithContext(ctx context.Context) AuditConfigurationOutput
}

func (*AuditConfiguration) ElementType() reflect.Type {
	return reflect.TypeOf((*AuditConfiguration)(nil))
}

func (i *AuditConfiguration) ToAuditConfigurationOutput() AuditConfigurationOutput {
	return i.ToAuditConfigurationOutputWithContext(context.Background())
}

func (i *AuditConfiguration) ToAuditConfigurationOutputWithContext(ctx context.Context) AuditConfigurationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AuditConfigurationOutput)
}

func (i *AuditConfiguration) ToAuditConfigurationPtrOutput() AuditConfigurationPtrOutput {
	return i.ToAuditConfigurationPtrOutputWithContext(context.Background())
}

func (i *AuditConfiguration) ToAuditConfigurationPtrOutputWithContext(ctx context.Context) AuditConfigurationPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AuditConfigurationPtrOutput)
}

type AuditConfigurationPtrInput interface {
	pulumi.Input

	ToAuditConfigurationPtrOutput() AuditConfigurationPtrOutput
	ToAuditConfigurationPtrOutputWithContext(ctx context.Context) AuditConfigurationPtrOutput
}

type auditConfigurationPtrType AuditConfigurationArgs

func (*auditConfigurationPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**AuditConfiguration)(nil))
}

func (i *auditConfigurationPtrType) ToAuditConfigurationPtrOutput() AuditConfigurationPtrOutput {
	return i.ToAuditConfigurationPtrOutputWithContext(context.Background())
}

func (i *auditConfigurationPtrType) ToAuditConfigurationPtrOutputWithContext(ctx context.Context) AuditConfigurationPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AuditConfigurationPtrOutput)
}

// AuditConfigurationArrayInput is an input type that accepts AuditConfigurationArray and AuditConfigurationArrayOutput values.
// You can construct a concrete instance of `AuditConfigurationArrayInput` via:
//
//          AuditConfigurationArray{ AuditConfigurationArgs{...} }
type AuditConfigurationArrayInput interface {
	pulumi.Input

	ToAuditConfigurationArrayOutput() AuditConfigurationArrayOutput
	ToAuditConfigurationArrayOutputWithContext(context.Context) AuditConfigurationArrayOutput
}

type AuditConfigurationArray []AuditConfigurationInput

func (AuditConfigurationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AuditConfiguration)(nil)).Elem()
}

func (i AuditConfigurationArray) ToAuditConfigurationArrayOutput() AuditConfigurationArrayOutput {
	return i.ToAuditConfigurationArrayOutputWithContext(context.Background())
}

func (i AuditConfigurationArray) ToAuditConfigurationArrayOutputWithContext(ctx context.Context) AuditConfigurationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AuditConfigurationArrayOutput)
}

// AuditConfigurationMapInput is an input type that accepts AuditConfigurationMap and AuditConfigurationMapOutput values.
// You can construct a concrete instance of `AuditConfigurationMapInput` via:
//
//          AuditConfigurationMap{ "key": AuditConfigurationArgs{...} }
type AuditConfigurationMapInput interface {
	pulumi.Input

	ToAuditConfigurationMapOutput() AuditConfigurationMapOutput
	ToAuditConfigurationMapOutputWithContext(context.Context) AuditConfigurationMapOutput
}

type AuditConfigurationMap map[string]AuditConfigurationInput

func (AuditConfigurationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AuditConfiguration)(nil)).Elem()
}

func (i AuditConfigurationMap) ToAuditConfigurationMapOutput() AuditConfigurationMapOutput {
	return i.ToAuditConfigurationMapOutputWithContext(context.Background())
}

func (i AuditConfigurationMap) ToAuditConfigurationMapOutputWithContext(ctx context.Context) AuditConfigurationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AuditConfigurationMapOutput)
}

type AuditConfigurationOutput struct {
	*pulumi.OutputState
}

func (AuditConfigurationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*AuditConfiguration)(nil))
}

func (o AuditConfigurationOutput) ToAuditConfigurationOutput() AuditConfigurationOutput {
	return o
}

func (o AuditConfigurationOutput) ToAuditConfigurationOutputWithContext(ctx context.Context) AuditConfigurationOutput {
	return o
}

func (o AuditConfigurationOutput) ToAuditConfigurationPtrOutput() AuditConfigurationPtrOutput {
	return o.ToAuditConfigurationPtrOutputWithContext(context.Background())
}

func (o AuditConfigurationOutput) ToAuditConfigurationPtrOutputWithContext(ctx context.Context) AuditConfigurationPtrOutput {
	return o.ApplyT(func(v AuditConfiguration) *AuditConfiguration {
		return &v
	}).(AuditConfigurationPtrOutput)
}

type AuditConfigurationPtrOutput struct {
	*pulumi.OutputState
}

func (AuditConfigurationPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**AuditConfiguration)(nil))
}

func (o AuditConfigurationPtrOutput) ToAuditConfigurationPtrOutput() AuditConfigurationPtrOutput {
	return o
}

func (o AuditConfigurationPtrOutput) ToAuditConfigurationPtrOutputWithContext(ctx context.Context) AuditConfigurationPtrOutput {
	return o
}

type AuditConfigurationArrayOutput struct{ *pulumi.OutputState }

func (AuditConfigurationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]AuditConfiguration)(nil))
}

func (o AuditConfigurationArrayOutput) ToAuditConfigurationArrayOutput() AuditConfigurationArrayOutput {
	return o
}

func (o AuditConfigurationArrayOutput) ToAuditConfigurationArrayOutputWithContext(ctx context.Context) AuditConfigurationArrayOutput {
	return o
}

func (o AuditConfigurationArrayOutput) Index(i pulumi.IntInput) AuditConfigurationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) AuditConfiguration {
		return vs[0].([]AuditConfiguration)[vs[1].(int)]
	}).(AuditConfigurationOutput)
}

type AuditConfigurationMapOutput struct{ *pulumi.OutputState }

func (AuditConfigurationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]AuditConfiguration)(nil))
}

func (o AuditConfigurationMapOutput) ToAuditConfigurationMapOutput() AuditConfigurationMapOutput {
	return o
}

func (o AuditConfigurationMapOutput) ToAuditConfigurationMapOutputWithContext(ctx context.Context) AuditConfigurationMapOutput {
	return o
}

func (o AuditConfigurationMapOutput) MapIndex(k pulumi.StringInput) AuditConfigurationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) AuditConfiguration {
		return vs[0].(map[string]AuditConfiguration)[vs[1].(string)]
	}).(AuditConfigurationOutput)
}

func init() {
	pulumi.RegisterOutputType(AuditConfigurationOutput{})
	pulumi.RegisterOutputType(AuditConfigurationPtrOutput{})
	pulumi.RegisterOutputType(AuditConfigurationArrayOutput{})
	pulumi.RegisterOutputType(AuditConfigurationMapOutput{})
}
