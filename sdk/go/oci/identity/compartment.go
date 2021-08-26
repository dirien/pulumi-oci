// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// ## Import
//
// Compartments can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:identity/compartment:Compartment test_compartment "id"
// ```
type Compartment struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the parent compartment containing the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) The description you assign to the compartment during creation. Does not have to be unique, and it's changeable.
	Description pulumi.StringOutput `pulumi:"description"`
	// Defaults to false. If omitted or set to false the provider will implicitly import the compartment if there is a name collision, and will not actually delete the compartment on destroy or removal of the resource declaration. If set to true, the provider will throw an error on a name collision with another compartment, and will attempt to delete the compartment on destroy or removal of the resource declaration.
	EnableDelete pulumi.BoolPtrOutput `pulumi:"enableDelete"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The detailed status of INACTIVE lifecycleState.
	InactiveState pulumi.StringOutput `pulumi:"inactiveState"`
	// Indicates whether or not the compartment is accessible for the user making the request. Returns true when the user has INSPECT permissions directly on a resource in the compartment or indirectly (permissions can be on a resource in a subcompartment).
	IsAccessible pulumi.BoolOutput `pulumi:"isAccessible"`
	// (Updatable) The name you assign to the compartment during creation. The name must be unique across all compartments in the parent compartment. Avoid entering confidential information.
	Name pulumi.StringOutput `pulumi:"name"`
	// The compartment's current state.
	State pulumi.StringOutput `pulumi:"state"`
	// Date and time the compartment was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewCompartment registers a new resource with the given unique name, arguments, and options.
func NewCompartment(ctx *pulumi.Context,
	name string, args *CompartmentArgs, opts ...pulumi.ResourceOption) (*Compartment, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Description == nil {
		return nil, errors.New("invalid value for required argument 'Description'")
	}
	var resource Compartment
	err := ctx.RegisterResource("oci:identity/compartment:Compartment", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCompartment gets an existing Compartment resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCompartment(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CompartmentState, opts ...pulumi.ResourceOption) (*Compartment, error) {
	var resource Compartment
	err := ctx.ReadResource("oci:identity/compartment:Compartment", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Compartment resources.
type compartmentState struct {
	// (Updatable) The OCID of the parent compartment containing the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description you assign to the compartment during creation. Does not have to be unique, and it's changeable.
	Description *string `pulumi:"description"`
	// Defaults to false. If omitted or set to false the provider will implicitly import the compartment if there is a name collision, and will not actually delete the compartment on destroy or removal of the resource declaration. If set to true, the provider will throw an error on a name collision with another compartment, and will attempt to delete the compartment on destroy or removal of the resource declaration.
	EnableDelete *bool `pulumi:"enableDelete"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The detailed status of INACTIVE lifecycleState.
	InactiveState *string `pulumi:"inactiveState"`
	// Indicates whether or not the compartment is accessible for the user making the request. Returns true when the user has INSPECT permissions directly on a resource in the compartment or indirectly (permissions can be on a resource in a subcompartment).
	IsAccessible *bool `pulumi:"isAccessible"`
	// (Updatable) The name you assign to the compartment during creation. The name must be unique across all compartments in the parent compartment. Avoid entering confidential information.
	Name *string `pulumi:"name"`
	// The compartment's current state.
	State *string `pulumi:"state"`
	// Date and time the compartment was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type CompartmentState struct {
	// (Updatable) The OCID of the parent compartment containing the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description you assign to the compartment during creation. Does not have to be unique, and it's changeable.
	Description pulumi.StringPtrInput
	// Defaults to false. If omitted or set to false the provider will implicitly import the compartment if there is a name collision, and will not actually delete the compartment on destroy or removal of the resource declaration. If set to true, the provider will throw an error on a name collision with another compartment, and will attempt to delete the compartment on destroy or removal of the resource declaration.
	EnableDelete pulumi.BoolPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The detailed status of INACTIVE lifecycleState.
	InactiveState pulumi.StringPtrInput
	// Indicates whether or not the compartment is accessible for the user making the request. Returns true when the user has INSPECT permissions directly on a resource in the compartment or indirectly (permissions can be on a resource in a subcompartment).
	IsAccessible pulumi.BoolPtrInput
	// (Updatable) The name you assign to the compartment during creation. The name must be unique across all compartments in the parent compartment. Avoid entering confidential information.
	Name pulumi.StringPtrInput
	// The compartment's current state.
	State pulumi.StringPtrInput
	// Date and time the compartment was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (CompartmentState) ElementType() reflect.Type {
	return reflect.TypeOf((*compartmentState)(nil)).Elem()
}

type compartmentArgs struct {
	// (Updatable) The OCID of the parent compartment containing the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description you assign to the compartment during creation. Does not have to be unique, and it's changeable.
	Description string `pulumi:"description"`
	// Defaults to false. If omitted or set to false the provider will implicitly import the compartment if there is a name collision, and will not actually delete the compartment on destroy or removal of the resource declaration. If set to true, the provider will throw an error on a name collision with another compartment, and will attempt to delete the compartment on destroy or removal of the resource declaration.
	EnableDelete *bool `pulumi:"enableDelete"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The name you assign to the compartment during creation. The name must be unique across all compartments in the parent compartment. Avoid entering confidential information.
	Name *string `pulumi:"name"`
}

// The set of arguments for constructing a Compartment resource.
type CompartmentArgs struct {
	// (Updatable) The OCID of the parent compartment containing the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description you assign to the compartment during creation. Does not have to be unique, and it's changeable.
	Description pulumi.StringInput
	// Defaults to false. If omitted or set to false the provider will implicitly import the compartment if there is a name collision, and will not actually delete the compartment on destroy or removal of the resource declaration. If set to true, the provider will throw an error on a name collision with another compartment, and will attempt to delete the compartment on destroy or removal of the resource declaration.
	EnableDelete pulumi.BoolPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The name you assign to the compartment during creation. The name must be unique across all compartments in the parent compartment. Avoid entering confidential information.
	Name pulumi.StringPtrInput
}

func (CompartmentArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*compartmentArgs)(nil)).Elem()
}

type CompartmentInput interface {
	pulumi.Input

	ToCompartmentOutput() CompartmentOutput
	ToCompartmentOutputWithContext(ctx context.Context) CompartmentOutput
}

func (*Compartment) ElementType() reflect.Type {
	return reflect.TypeOf((*Compartment)(nil))
}

func (i *Compartment) ToCompartmentOutput() CompartmentOutput {
	return i.ToCompartmentOutputWithContext(context.Background())
}

func (i *Compartment) ToCompartmentOutputWithContext(ctx context.Context) CompartmentOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CompartmentOutput)
}

func (i *Compartment) ToCompartmentPtrOutput() CompartmentPtrOutput {
	return i.ToCompartmentPtrOutputWithContext(context.Background())
}

func (i *Compartment) ToCompartmentPtrOutputWithContext(ctx context.Context) CompartmentPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CompartmentPtrOutput)
}

type CompartmentPtrInput interface {
	pulumi.Input

	ToCompartmentPtrOutput() CompartmentPtrOutput
	ToCompartmentPtrOutputWithContext(ctx context.Context) CompartmentPtrOutput
}

type compartmentPtrType CompartmentArgs

func (*compartmentPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**Compartment)(nil))
}

func (i *compartmentPtrType) ToCompartmentPtrOutput() CompartmentPtrOutput {
	return i.ToCompartmentPtrOutputWithContext(context.Background())
}

func (i *compartmentPtrType) ToCompartmentPtrOutputWithContext(ctx context.Context) CompartmentPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CompartmentPtrOutput)
}

// CompartmentArrayInput is an input type that accepts CompartmentArray and CompartmentArrayOutput values.
// You can construct a concrete instance of `CompartmentArrayInput` via:
//
//          CompartmentArray{ CompartmentArgs{...} }
type CompartmentArrayInput interface {
	pulumi.Input

	ToCompartmentArrayOutput() CompartmentArrayOutput
	ToCompartmentArrayOutputWithContext(context.Context) CompartmentArrayOutput
}

type CompartmentArray []CompartmentInput

func (CompartmentArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Compartment)(nil)).Elem()
}

func (i CompartmentArray) ToCompartmentArrayOutput() CompartmentArrayOutput {
	return i.ToCompartmentArrayOutputWithContext(context.Background())
}

func (i CompartmentArray) ToCompartmentArrayOutputWithContext(ctx context.Context) CompartmentArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CompartmentArrayOutput)
}

// CompartmentMapInput is an input type that accepts CompartmentMap and CompartmentMapOutput values.
// You can construct a concrete instance of `CompartmentMapInput` via:
//
//          CompartmentMap{ "key": CompartmentArgs{...} }
type CompartmentMapInput interface {
	pulumi.Input

	ToCompartmentMapOutput() CompartmentMapOutput
	ToCompartmentMapOutputWithContext(context.Context) CompartmentMapOutput
}

type CompartmentMap map[string]CompartmentInput

func (CompartmentMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Compartment)(nil)).Elem()
}

func (i CompartmentMap) ToCompartmentMapOutput() CompartmentMapOutput {
	return i.ToCompartmentMapOutputWithContext(context.Background())
}

func (i CompartmentMap) ToCompartmentMapOutputWithContext(ctx context.Context) CompartmentMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CompartmentMapOutput)
}

type CompartmentOutput struct {
	*pulumi.OutputState
}

func (CompartmentOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*Compartment)(nil))
}

func (o CompartmentOutput) ToCompartmentOutput() CompartmentOutput {
	return o
}

func (o CompartmentOutput) ToCompartmentOutputWithContext(ctx context.Context) CompartmentOutput {
	return o
}

func (o CompartmentOutput) ToCompartmentPtrOutput() CompartmentPtrOutput {
	return o.ToCompartmentPtrOutputWithContext(context.Background())
}

func (o CompartmentOutput) ToCompartmentPtrOutputWithContext(ctx context.Context) CompartmentPtrOutput {
	return o.ApplyT(func(v Compartment) *Compartment {
		return &v
	}).(CompartmentPtrOutput)
}

type CompartmentPtrOutput struct {
	*pulumi.OutputState
}

func (CompartmentPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Compartment)(nil))
}

func (o CompartmentPtrOutput) ToCompartmentPtrOutput() CompartmentPtrOutput {
	return o
}

func (o CompartmentPtrOutput) ToCompartmentPtrOutputWithContext(ctx context.Context) CompartmentPtrOutput {
	return o
}

type CompartmentArrayOutput struct{ *pulumi.OutputState }

func (CompartmentArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]Compartment)(nil))
}

func (o CompartmentArrayOutput) ToCompartmentArrayOutput() CompartmentArrayOutput {
	return o
}

func (o CompartmentArrayOutput) ToCompartmentArrayOutputWithContext(ctx context.Context) CompartmentArrayOutput {
	return o
}

func (o CompartmentArrayOutput) Index(i pulumi.IntInput) CompartmentOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) Compartment {
		return vs[0].([]Compartment)[vs[1].(int)]
	}).(CompartmentOutput)
}

type CompartmentMapOutput struct{ *pulumi.OutputState }

func (CompartmentMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]Compartment)(nil))
}

func (o CompartmentMapOutput) ToCompartmentMapOutput() CompartmentMapOutput {
	return o
}

func (o CompartmentMapOutput) ToCompartmentMapOutputWithContext(ctx context.Context) CompartmentMapOutput {
	return o
}

func (o CompartmentMapOutput) MapIndex(k pulumi.StringInput) CompartmentOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) Compartment {
		return vs[0].(map[string]Compartment)[vs[1].(string)]
	}).(CompartmentOutput)
}

func init() {
	pulumi.RegisterOutputType(CompartmentOutput{})
	pulumi.RegisterOutputType(CompartmentPtrOutput{})
	pulumi.RegisterOutputType(CompartmentArrayOutput{})
	pulumi.RegisterOutputType(CompartmentMapOutput{})
}