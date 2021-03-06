// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type CoreDefaultDhcpOptions struct {
	pulumi.CustomResourceState

	CompartmentId           pulumi.StringOutput                     `pulumi:"compartmentId"`
	DefinedTags             pulumi.MapOutput                        `pulumi:"definedTags"`
	DisplayName             pulumi.StringOutput                     `pulumi:"displayName"`
	DomainNameType          pulumi.StringOutput                     `pulumi:"domainNameType"`
	FreeformTags            pulumi.MapOutput                        `pulumi:"freeformTags"`
	ManageDefaultResourceId pulumi.StringOutput                     `pulumi:"manageDefaultResourceId"`
	Options                 CoreDefaultDhcpOptionsOptionArrayOutput `pulumi:"options"`
	State                   pulumi.StringOutput                     `pulumi:"state"`
	TimeCreated             pulumi.StringOutput                     `pulumi:"timeCreated"`
}

// NewCoreDefaultDhcpOptions registers a new resource with the given unique name, arguments, and options.
func NewCoreDefaultDhcpOptions(ctx *pulumi.Context,
	name string, args *CoreDefaultDhcpOptionsArgs, opts ...pulumi.ResourceOption) (*CoreDefaultDhcpOptions, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ManageDefaultResourceId == nil {
		return nil, errors.New("invalid value for required argument 'ManageDefaultResourceId'")
	}
	if args.Options == nil {
		return nil, errors.New("invalid value for required argument 'Options'")
	}
	var resource CoreDefaultDhcpOptions
	err := ctx.RegisterResource("oci:index/coreDefaultDhcpOptions:CoreDefaultDhcpOptions", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCoreDefaultDhcpOptions gets an existing CoreDefaultDhcpOptions resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCoreDefaultDhcpOptions(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CoreDefaultDhcpOptionsState, opts ...pulumi.ResourceOption) (*CoreDefaultDhcpOptions, error) {
	var resource CoreDefaultDhcpOptions
	err := ctx.ReadResource("oci:index/coreDefaultDhcpOptions:CoreDefaultDhcpOptions", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CoreDefaultDhcpOptions resources.
type coreDefaultDhcpOptionsState struct {
	CompartmentId           *string                        `pulumi:"compartmentId"`
	DefinedTags             map[string]interface{}         `pulumi:"definedTags"`
	DisplayName             *string                        `pulumi:"displayName"`
	DomainNameType          *string                        `pulumi:"domainNameType"`
	FreeformTags            map[string]interface{}         `pulumi:"freeformTags"`
	ManageDefaultResourceId *string                        `pulumi:"manageDefaultResourceId"`
	Options                 []CoreDefaultDhcpOptionsOption `pulumi:"options"`
	State                   *string                        `pulumi:"state"`
	TimeCreated             *string                        `pulumi:"timeCreated"`
}

type CoreDefaultDhcpOptionsState struct {
	CompartmentId           pulumi.StringPtrInput
	DefinedTags             pulumi.MapInput
	DisplayName             pulumi.StringPtrInput
	DomainNameType          pulumi.StringPtrInput
	FreeformTags            pulumi.MapInput
	ManageDefaultResourceId pulumi.StringPtrInput
	Options                 CoreDefaultDhcpOptionsOptionArrayInput
	State                   pulumi.StringPtrInput
	TimeCreated             pulumi.StringPtrInput
}

func (CoreDefaultDhcpOptionsState) ElementType() reflect.Type {
	return reflect.TypeOf((*coreDefaultDhcpOptionsState)(nil)).Elem()
}

type coreDefaultDhcpOptionsArgs struct {
	CompartmentId           *string                        `pulumi:"compartmentId"`
	DefinedTags             map[string]interface{}         `pulumi:"definedTags"`
	DisplayName             *string                        `pulumi:"displayName"`
	DomainNameType          *string                        `pulumi:"domainNameType"`
	FreeformTags            map[string]interface{}         `pulumi:"freeformTags"`
	ManageDefaultResourceId string                         `pulumi:"manageDefaultResourceId"`
	Options                 []CoreDefaultDhcpOptionsOption `pulumi:"options"`
}

// The set of arguments for constructing a CoreDefaultDhcpOptions resource.
type CoreDefaultDhcpOptionsArgs struct {
	CompartmentId           pulumi.StringPtrInput
	DefinedTags             pulumi.MapInput
	DisplayName             pulumi.StringPtrInput
	DomainNameType          pulumi.StringPtrInput
	FreeformTags            pulumi.MapInput
	ManageDefaultResourceId pulumi.StringInput
	Options                 CoreDefaultDhcpOptionsOptionArrayInput
}

func (CoreDefaultDhcpOptionsArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*coreDefaultDhcpOptionsArgs)(nil)).Elem()
}

type CoreDefaultDhcpOptionsInput interface {
	pulumi.Input

	ToCoreDefaultDhcpOptionsOutput() CoreDefaultDhcpOptionsOutput
	ToCoreDefaultDhcpOptionsOutputWithContext(ctx context.Context) CoreDefaultDhcpOptionsOutput
}

func (*CoreDefaultDhcpOptions) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreDefaultDhcpOptions)(nil))
}

func (i *CoreDefaultDhcpOptions) ToCoreDefaultDhcpOptionsOutput() CoreDefaultDhcpOptionsOutput {
	return i.ToCoreDefaultDhcpOptionsOutputWithContext(context.Background())
}

func (i *CoreDefaultDhcpOptions) ToCoreDefaultDhcpOptionsOutputWithContext(ctx context.Context) CoreDefaultDhcpOptionsOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDefaultDhcpOptionsOutput)
}

func (i *CoreDefaultDhcpOptions) ToCoreDefaultDhcpOptionsPtrOutput() CoreDefaultDhcpOptionsPtrOutput {
	return i.ToCoreDefaultDhcpOptionsPtrOutputWithContext(context.Background())
}

func (i *CoreDefaultDhcpOptions) ToCoreDefaultDhcpOptionsPtrOutputWithContext(ctx context.Context) CoreDefaultDhcpOptionsPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDefaultDhcpOptionsPtrOutput)
}

type CoreDefaultDhcpOptionsPtrInput interface {
	pulumi.Input

	ToCoreDefaultDhcpOptionsPtrOutput() CoreDefaultDhcpOptionsPtrOutput
	ToCoreDefaultDhcpOptionsPtrOutputWithContext(ctx context.Context) CoreDefaultDhcpOptionsPtrOutput
}

type coreDefaultDhcpOptionsPtrType CoreDefaultDhcpOptionsArgs

func (*coreDefaultDhcpOptionsPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreDefaultDhcpOptions)(nil))
}

func (i *coreDefaultDhcpOptionsPtrType) ToCoreDefaultDhcpOptionsPtrOutput() CoreDefaultDhcpOptionsPtrOutput {
	return i.ToCoreDefaultDhcpOptionsPtrOutputWithContext(context.Background())
}

func (i *coreDefaultDhcpOptionsPtrType) ToCoreDefaultDhcpOptionsPtrOutputWithContext(ctx context.Context) CoreDefaultDhcpOptionsPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDefaultDhcpOptionsPtrOutput)
}

// CoreDefaultDhcpOptionsArrayInput is an input type that accepts CoreDefaultDhcpOptionsArray and CoreDefaultDhcpOptionsArrayOutput values.
// You can construct a concrete instance of `CoreDefaultDhcpOptionsArrayInput` via:
//
//          CoreDefaultDhcpOptionsArray{ CoreDefaultDhcpOptionsArgs{...} }
type CoreDefaultDhcpOptionsArrayInput interface {
	pulumi.Input

	ToCoreDefaultDhcpOptionsArrayOutput() CoreDefaultDhcpOptionsArrayOutput
	ToCoreDefaultDhcpOptionsArrayOutputWithContext(context.Context) CoreDefaultDhcpOptionsArrayOutput
}

type CoreDefaultDhcpOptionsArray []CoreDefaultDhcpOptionsInput

func (CoreDefaultDhcpOptionsArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CoreDefaultDhcpOptions)(nil)).Elem()
}

func (i CoreDefaultDhcpOptionsArray) ToCoreDefaultDhcpOptionsArrayOutput() CoreDefaultDhcpOptionsArrayOutput {
	return i.ToCoreDefaultDhcpOptionsArrayOutputWithContext(context.Background())
}

func (i CoreDefaultDhcpOptionsArray) ToCoreDefaultDhcpOptionsArrayOutputWithContext(ctx context.Context) CoreDefaultDhcpOptionsArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDefaultDhcpOptionsArrayOutput)
}

// CoreDefaultDhcpOptionsMapInput is an input type that accepts CoreDefaultDhcpOptionsMap and CoreDefaultDhcpOptionsMapOutput values.
// You can construct a concrete instance of `CoreDefaultDhcpOptionsMapInput` via:
//
//          CoreDefaultDhcpOptionsMap{ "key": CoreDefaultDhcpOptionsArgs{...} }
type CoreDefaultDhcpOptionsMapInput interface {
	pulumi.Input

	ToCoreDefaultDhcpOptionsMapOutput() CoreDefaultDhcpOptionsMapOutput
	ToCoreDefaultDhcpOptionsMapOutputWithContext(context.Context) CoreDefaultDhcpOptionsMapOutput
}

type CoreDefaultDhcpOptionsMap map[string]CoreDefaultDhcpOptionsInput

func (CoreDefaultDhcpOptionsMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CoreDefaultDhcpOptions)(nil)).Elem()
}

func (i CoreDefaultDhcpOptionsMap) ToCoreDefaultDhcpOptionsMapOutput() CoreDefaultDhcpOptionsMapOutput {
	return i.ToCoreDefaultDhcpOptionsMapOutputWithContext(context.Background())
}

func (i CoreDefaultDhcpOptionsMap) ToCoreDefaultDhcpOptionsMapOutputWithContext(ctx context.Context) CoreDefaultDhcpOptionsMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDefaultDhcpOptionsMapOutput)
}

type CoreDefaultDhcpOptionsOutput struct {
	*pulumi.OutputState
}

func (CoreDefaultDhcpOptionsOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreDefaultDhcpOptions)(nil))
}

func (o CoreDefaultDhcpOptionsOutput) ToCoreDefaultDhcpOptionsOutput() CoreDefaultDhcpOptionsOutput {
	return o
}

func (o CoreDefaultDhcpOptionsOutput) ToCoreDefaultDhcpOptionsOutputWithContext(ctx context.Context) CoreDefaultDhcpOptionsOutput {
	return o
}

func (o CoreDefaultDhcpOptionsOutput) ToCoreDefaultDhcpOptionsPtrOutput() CoreDefaultDhcpOptionsPtrOutput {
	return o.ToCoreDefaultDhcpOptionsPtrOutputWithContext(context.Background())
}

func (o CoreDefaultDhcpOptionsOutput) ToCoreDefaultDhcpOptionsPtrOutputWithContext(ctx context.Context) CoreDefaultDhcpOptionsPtrOutput {
	return o.ApplyT(func(v CoreDefaultDhcpOptions) *CoreDefaultDhcpOptions {
		return &v
	}).(CoreDefaultDhcpOptionsPtrOutput)
}

type CoreDefaultDhcpOptionsPtrOutput struct {
	*pulumi.OutputState
}

func (CoreDefaultDhcpOptionsPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreDefaultDhcpOptions)(nil))
}

func (o CoreDefaultDhcpOptionsPtrOutput) ToCoreDefaultDhcpOptionsPtrOutput() CoreDefaultDhcpOptionsPtrOutput {
	return o
}

func (o CoreDefaultDhcpOptionsPtrOutput) ToCoreDefaultDhcpOptionsPtrOutputWithContext(ctx context.Context) CoreDefaultDhcpOptionsPtrOutput {
	return o
}

type CoreDefaultDhcpOptionsArrayOutput struct{ *pulumi.OutputState }

func (CoreDefaultDhcpOptionsArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CoreDefaultDhcpOptions)(nil))
}

func (o CoreDefaultDhcpOptionsArrayOutput) ToCoreDefaultDhcpOptionsArrayOutput() CoreDefaultDhcpOptionsArrayOutput {
	return o
}

func (o CoreDefaultDhcpOptionsArrayOutput) ToCoreDefaultDhcpOptionsArrayOutputWithContext(ctx context.Context) CoreDefaultDhcpOptionsArrayOutput {
	return o
}

func (o CoreDefaultDhcpOptionsArrayOutput) Index(i pulumi.IntInput) CoreDefaultDhcpOptionsOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CoreDefaultDhcpOptions {
		return vs[0].([]CoreDefaultDhcpOptions)[vs[1].(int)]
	}).(CoreDefaultDhcpOptionsOutput)
}

type CoreDefaultDhcpOptionsMapOutput struct{ *pulumi.OutputState }

func (CoreDefaultDhcpOptionsMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CoreDefaultDhcpOptions)(nil))
}

func (o CoreDefaultDhcpOptionsMapOutput) ToCoreDefaultDhcpOptionsMapOutput() CoreDefaultDhcpOptionsMapOutput {
	return o
}

func (o CoreDefaultDhcpOptionsMapOutput) ToCoreDefaultDhcpOptionsMapOutputWithContext(ctx context.Context) CoreDefaultDhcpOptionsMapOutput {
	return o
}

func (o CoreDefaultDhcpOptionsMapOutput) MapIndex(k pulumi.StringInput) CoreDefaultDhcpOptionsOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CoreDefaultDhcpOptions {
		return vs[0].(map[string]CoreDefaultDhcpOptions)[vs[1].(string)]
	}).(CoreDefaultDhcpOptionsOutput)
}

func init() {
	pulumi.RegisterOutputType(CoreDefaultDhcpOptionsOutput{})
	pulumi.RegisterOutputType(CoreDefaultDhcpOptionsPtrOutput{})
	pulumi.RegisterOutputType(CoreDefaultDhcpOptionsArrayOutput{})
	pulumi.RegisterOutputType(CoreDefaultDhcpOptionsMapOutput{})
}
