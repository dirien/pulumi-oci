// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Apm Domain resource in Oracle Cloud Infrastructure Apm service.
//
// Creates a new APM Domain.
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
// 		_, err := oci.NewApmApmDomain(ctx, "testApmDomain", &oci.ApmApmDomainArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			DisplayName:   pulumi.Any(_var.Apm_domain_display_name),
// 			DefinedTags: pulumi.AnyMap{
// 				"foo-namespace.bar-key": pulumi.Any("value"),
// 			},
// 			Description: pulumi.Any(_var.Apm_domain_description),
// 			FreeformTags: pulumi.AnyMap{
// 				"bar-key": pulumi.Any("value"),
// 			},
// 			IsFreeTier: pulumi.Any(_var.Apm_domain_is_free_tier),
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
// ApmDomains can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/apmApmDomain:ApmApmDomain test_apm_domain "id"
// ```
type ApmApmDomain struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment corresponding to the APM Domain.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Where APM Agents upload their observations and metrics.
	DataUploadEndpoint pulumi.StringOutput `pulumi:"dataUploadEndpoint"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Description of the APM Domain
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Display name of the APM Domain
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// Indicates whether this is an "Always Free" resource. The default value is false.
	IsFreeTier pulumi.BoolOutput `pulumi:"isFreeTier"`
	// The current lifecycle state of the APM Domain.
	State pulumi.StringOutput `pulumi:"state"`
	// The time the the APM Domain was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the APM Domain was updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewApmApmDomain registers a new resource with the given unique name, arguments, and options.
func NewApmApmDomain(ctx *pulumi.Context,
	name string, args *ApmApmDomainArgs, opts ...pulumi.ResourceOption) (*ApmApmDomain, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	var resource ApmApmDomain
	err := ctx.RegisterResource("oci:index/apmApmDomain:ApmApmDomain", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetApmApmDomain gets an existing ApmApmDomain resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetApmApmDomain(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ApmApmDomainState, opts ...pulumi.ResourceOption) (*ApmApmDomain, error) {
	var resource ApmApmDomain
	err := ctx.ReadResource("oci:index/apmApmDomain:ApmApmDomain", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ApmApmDomain resources.
type apmApmDomainState struct {
	// (Updatable) The OCID of the compartment corresponding to the APM Domain.
	CompartmentId *string `pulumi:"compartmentId"`
	// Where APM Agents upload their observations and metrics.
	DataUploadEndpoint *string `pulumi:"dataUploadEndpoint"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Description of the APM Domain
	Description *string `pulumi:"description"`
	// (Updatable) Display name of the APM Domain
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Indicates whether this is an "Always Free" resource. The default value is false.
	IsFreeTier *bool `pulumi:"isFreeTier"`
	// The current lifecycle state of the APM Domain.
	State *string `pulumi:"state"`
	// The time the the APM Domain was created. An RFC3339 formatted datetime string
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the APM Domain was updated. An RFC3339 formatted datetime string
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type ApmApmDomainState struct {
	// (Updatable) The OCID of the compartment corresponding to the APM Domain.
	CompartmentId pulumi.StringPtrInput
	// Where APM Agents upload their observations and metrics.
	DataUploadEndpoint pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Description of the APM Domain
	Description pulumi.StringPtrInput
	// (Updatable) Display name of the APM Domain
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// Indicates whether this is an "Always Free" resource. The default value is false.
	IsFreeTier pulumi.BoolPtrInput
	// The current lifecycle state of the APM Domain.
	State pulumi.StringPtrInput
	// The time the the APM Domain was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringPtrInput
	// The time the APM Domain was updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringPtrInput
}

func (ApmApmDomainState) ElementType() reflect.Type {
	return reflect.TypeOf((*apmApmDomainState)(nil)).Elem()
}

type apmApmDomainArgs struct {
	// (Updatable) The OCID of the compartment corresponding to the APM Domain.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Description of the APM Domain
	Description *string `pulumi:"description"`
	// (Updatable) Display name of the APM Domain
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Indicates whether this is an "Always Free" resource. The default value is false.
	IsFreeTier *bool `pulumi:"isFreeTier"`
}

// The set of arguments for constructing a ApmApmDomain resource.
type ApmApmDomainArgs struct {
	// (Updatable) The OCID of the compartment corresponding to the APM Domain.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Description of the APM Domain
	Description pulumi.StringPtrInput
	// (Updatable) Display name of the APM Domain
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// Indicates whether this is an "Always Free" resource. The default value is false.
	IsFreeTier pulumi.BoolPtrInput
}

func (ApmApmDomainArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*apmApmDomainArgs)(nil)).Elem()
}

type ApmApmDomainInput interface {
	pulumi.Input

	ToApmApmDomainOutput() ApmApmDomainOutput
	ToApmApmDomainOutputWithContext(ctx context.Context) ApmApmDomainOutput
}

func (*ApmApmDomain) ElementType() reflect.Type {
	return reflect.TypeOf((*ApmApmDomain)(nil))
}

func (i *ApmApmDomain) ToApmApmDomainOutput() ApmApmDomainOutput {
	return i.ToApmApmDomainOutputWithContext(context.Background())
}

func (i *ApmApmDomain) ToApmApmDomainOutputWithContext(ctx context.Context) ApmApmDomainOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ApmApmDomainOutput)
}

func (i *ApmApmDomain) ToApmApmDomainPtrOutput() ApmApmDomainPtrOutput {
	return i.ToApmApmDomainPtrOutputWithContext(context.Background())
}

func (i *ApmApmDomain) ToApmApmDomainPtrOutputWithContext(ctx context.Context) ApmApmDomainPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ApmApmDomainPtrOutput)
}

type ApmApmDomainPtrInput interface {
	pulumi.Input

	ToApmApmDomainPtrOutput() ApmApmDomainPtrOutput
	ToApmApmDomainPtrOutputWithContext(ctx context.Context) ApmApmDomainPtrOutput
}

type apmApmDomainPtrType ApmApmDomainArgs

func (*apmApmDomainPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**ApmApmDomain)(nil))
}

func (i *apmApmDomainPtrType) ToApmApmDomainPtrOutput() ApmApmDomainPtrOutput {
	return i.ToApmApmDomainPtrOutputWithContext(context.Background())
}

func (i *apmApmDomainPtrType) ToApmApmDomainPtrOutputWithContext(ctx context.Context) ApmApmDomainPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ApmApmDomainPtrOutput)
}

// ApmApmDomainArrayInput is an input type that accepts ApmApmDomainArray and ApmApmDomainArrayOutput values.
// You can construct a concrete instance of `ApmApmDomainArrayInput` via:
//
//          ApmApmDomainArray{ ApmApmDomainArgs{...} }
type ApmApmDomainArrayInput interface {
	pulumi.Input

	ToApmApmDomainArrayOutput() ApmApmDomainArrayOutput
	ToApmApmDomainArrayOutputWithContext(context.Context) ApmApmDomainArrayOutput
}

type ApmApmDomainArray []ApmApmDomainInput

func (ApmApmDomainArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ApmApmDomain)(nil)).Elem()
}

func (i ApmApmDomainArray) ToApmApmDomainArrayOutput() ApmApmDomainArrayOutput {
	return i.ToApmApmDomainArrayOutputWithContext(context.Background())
}

func (i ApmApmDomainArray) ToApmApmDomainArrayOutputWithContext(ctx context.Context) ApmApmDomainArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ApmApmDomainArrayOutput)
}

// ApmApmDomainMapInput is an input type that accepts ApmApmDomainMap and ApmApmDomainMapOutput values.
// You can construct a concrete instance of `ApmApmDomainMapInput` via:
//
//          ApmApmDomainMap{ "key": ApmApmDomainArgs{...} }
type ApmApmDomainMapInput interface {
	pulumi.Input

	ToApmApmDomainMapOutput() ApmApmDomainMapOutput
	ToApmApmDomainMapOutputWithContext(context.Context) ApmApmDomainMapOutput
}

type ApmApmDomainMap map[string]ApmApmDomainInput

func (ApmApmDomainMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ApmApmDomain)(nil)).Elem()
}

func (i ApmApmDomainMap) ToApmApmDomainMapOutput() ApmApmDomainMapOutput {
	return i.ToApmApmDomainMapOutputWithContext(context.Background())
}

func (i ApmApmDomainMap) ToApmApmDomainMapOutputWithContext(ctx context.Context) ApmApmDomainMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ApmApmDomainMapOutput)
}

type ApmApmDomainOutput struct {
	*pulumi.OutputState
}

func (ApmApmDomainOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*ApmApmDomain)(nil))
}

func (o ApmApmDomainOutput) ToApmApmDomainOutput() ApmApmDomainOutput {
	return o
}

func (o ApmApmDomainOutput) ToApmApmDomainOutputWithContext(ctx context.Context) ApmApmDomainOutput {
	return o
}

func (o ApmApmDomainOutput) ToApmApmDomainPtrOutput() ApmApmDomainPtrOutput {
	return o.ToApmApmDomainPtrOutputWithContext(context.Background())
}

func (o ApmApmDomainOutput) ToApmApmDomainPtrOutputWithContext(ctx context.Context) ApmApmDomainPtrOutput {
	return o.ApplyT(func(v ApmApmDomain) *ApmApmDomain {
		return &v
	}).(ApmApmDomainPtrOutput)
}

type ApmApmDomainPtrOutput struct {
	*pulumi.OutputState
}

func (ApmApmDomainPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ApmApmDomain)(nil))
}

func (o ApmApmDomainPtrOutput) ToApmApmDomainPtrOutput() ApmApmDomainPtrOutput {
	return o
}

func (o ApmApmDomainPtrOutput) ToApmApmDomainPtrOutputWithContext(ctx context.Context) ApmApmDomainPtrOutput {
	return o
}

type ApmApmDomainArrayOutput struct{ *pulumi.OutputState }

func (ApmApmDomainArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]ApmApmDomain)(nil))
}

func (o ApmApmDomainArrayOutput) ToApmApmDomainArrayOutput() ApmApmDomainArrayOutput {
	return o
}

func (o ApmApmDomainArrayOutput) ToApmApmDomainArrayOutputWithContext(ctx context.Context) ApmApmDomainArrayOutput {
	return o
}

func (o ApmApmDomainArrayOutput) Index(i pulumi.IntInput) ApmApmDomainOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) ApmApmDomain {
		return vs[0].([]ApmApmDomain)[vs[1].(int)]
	}).(ApmApmDomainOutput)
}

type ApmApmDomainMapOutput struct{ *pulumi.OutputState }

func (ApmApmDomainMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]ApmApmDomain)(nil))
}

func (o ApmApmDomainMapOutput) ToApmApmDomainMapOutput() ApmApmDomainMapOutput {
	return o
}

func (o ApmApmDomainMapOutput) ToApmApmDomainMapOutputWithContext(ctx context.Context) ApmApmDomainMapOutput {
	return o
}

func (o ApmApmDomainMapOutput) MapIndex(k pulumi.StringInput) ApmApmDomainOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) ApmApmDomain {
		return vs[0].(map[string]ApmApmDomain)[vs[1].(string)]
	}).(ApmApmDomainOutput)
}

func init() {
	pulumi.RegisterOutputType(ApmApmDomainOutput{})
	pulumi.RegisterOutputType(ApmApmDomainPtrOutput{})
	pulumi.RegisterOutputType(ApmApmDomainArrayOutput{})
	pulumi.RegisterOutputType(ApmApmDomainMapOutput{})
}
