// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Responder Recipe resource in Oracle Cloud Infrastructure Cloud Guard service.
//
// Create a ResponderRecipe.
//
// ## Import
//
// ResponderRecipes can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/cloudGuardResponderRecipe:CloudGuardResponderRecipe test_responder_recipe "id"
// ```
type CloudGuardResponderRecipe struct {
	pulumi.CustomResourceState

	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) ResponderRecipe Description
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) ResponderRecipe Display Name
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// List of responder rules associated with the recipe
	EffectiveResponderRules CloudGuardResponderRecipeEffectiveResponderRuleArrayOutput `pulumi:"effectiveResponderRules"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Owner of ResponderRecipe
	Owner pulumi.StringOutput `pulumi:"owner"`
	// (Updatable) Responder Rules to override from source responder recipe
	ResponderRules CloudGuardResponderRecipeResponderRuleArrayOutput `pulumi:"responderRules"`
	// The id of the source responder recipe.
	SourceResponderRecipeId pulumi.StringOutput `pulumi:"sourceResponderRecipeId"`
	// The current state of the Example.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The date and time the responder recipe was created. Format defined by RFC3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the responder recipe was updated. Format defined by RFC3339.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewCloudGuardResponderRecipe registers a new resource with the given unique name, arguments, and options.
func NewCloudGuardResponderRecipe(ctx *pulumi.Context,
	name string, args *CloudGuardResponderRecipeArgs, opts ...pulumi.ResourceOption) (*CloudGuardResponderRecipe, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.SourceResponderRecipeId == nil {
		return nil, errors.New("invalid value for required argument 'SourceResponderRecipeId'")
	}
	var resource CloudGuardResponderRecipe
	err := ctx.RegisterResource("oci:index/cloudGuardResponderRecipe:CloudGuardResponderRecipe", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCloudGuardResponderRecipe gets an existing CloudGuardResponderRecipe resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCloudGuardResponderRecipe(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CloudGuardResponderRecipeState, opts ...pulumi.ResourceOption) (*CloudGuardResponderRecipe, error) {
	var resource CloudGuardResponderRecipe
	err := ctx.ReadResource("oci:index/cloudGuardResponderRecipe:CloudGuardResponderRecipe", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CloudGuardResponderRecipe resources.
type cloudGuardResponderRecipeState struct {
	// (Updatable) Compartment Identifier
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) ResponderRecipe Description
	Description *string `pulumi:"description"`
	// (Updatable) ResponderRecipe Display Name
	DisplayName *string `pulumi:"displayName"`
	// List of responder rules associated with the recipe
	EffectiveResponderRules []CloudGuardResponderRecipeEffectiveResponderRule `pulumi:"effectiveResponderRules"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Owner of ResponderRecipe
	Owner *string `pulumi:"owner"`
	// (Updatable) Responder Rules to override from source responder recipe
	ResponderRules []CloudGuardResponderRecipeResponderRule `pulumi:"responderRules"`
	// The id of the source responder recipe.
	SourceResponderRecipeId *string `pulumi:"sourceResponderRecipeId"`
	// The current state of the Example.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The date and time the responder recipe was created. Format defined by RFC3339.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the responder recipe was updated. Format defined by RFC3339.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type CloudGuardResponderRecipeState struct {
	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) ResponderRecipe Description
	Description pulumi.StringPtrInput
	// (Updatable) ResponderRecipe Display Name
	DisplayName pulumi.StringPtrInput
	// List of responder rules associated with the recipe
	EffectiveResponderRules CloudGuardResponderRecipeEffectiveResponderRuleArrayInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// Owner of ResponderRecipe
	Owner pulumi.StringPtrInput
	// (Updatable) Responder Rules to override from source responder recipe
	ResponderRules CloudGuardResponderRecipeResponderRuleArrayInput
	// The id of the source responder recipe.
	SourceResponderRecipeId pulumi.StringPtrInput
	// The current state of the Example.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The date and time the responder recipe was created. Format defined by RFC3339.
	TimeCreated pulumi.StringPtrInput
	// The date and time the responder recipe was updated. Format defined by RFC3339.
	TimeUpdated pulumi.StringPtrInput
}

func (CloudGuardResponderRecipeState) ElementType() reflect.Type {
	return reflect.TypeOf((*cloudGuardResponderRecipeState)(nil)).Elem()
}

type cloudGuardResponderRecipeArgs struct {
	// (Updatable) Compartment Identifier
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) ResponderRecipe Description
	Description *string `pulumi:"description"`
	// (Updatable) ResponderRecipe Display Name
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Responder Rules to override from source responder recipe
	ResponderRules []CloudGuardResponderRecipeResponderRule `pulumi:"responderRules"`
	// The id of the source responder recipe.
	SourceResponderRecipeId string `pulumi:"sourceResponderRecipeId"`
}

// The set of arguments for constructing a CloudGuardResponderRecipe resource.
type CloudGuardResponderRecipeArgs struct {
	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) ResponderRecipe Description
	Description pulumi.StringPtrInput
	// (Updatable) ResponderRecipe Display Name
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Responder Rules to override from source responder recipe
	ResponderRules CloudGuardResponderRecipeResponderRuleArrayInput
	// The id of the source responder recipe.
	SourceResponderRecipeId pulumi.StringInput
}

func (CloudGuardResponderRecipeArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*cloudGuardResponderRecipeArgs)(nil)).Elem()
}

type CloudGuardResponderRecipeInput interface {
	pulumi.Input

	ToCloudGuardResponderRecipeOutput() CloudGuardResponderRecipeOutput
	ToCloudGuardResponderRecipeOutputWithContext(ctx context.Context) CloudGuardResponderRecipeOutput
}

func (*CloudGuardResponderRecipe) ElementType() reflect.Type {
	return reflect.TypeOf((*CloudGuardResponderRecipe)(nil))
}

func (i *CloudGuardResponderRecipe) ToCloudGuardResponderRecipeOutput() CloudGuardResponderRecipeOutput {
	return i.ToCloudGuardResponderRecipeOutputWithContext(context.Background())
}

func (i *CloudGuardResponderRecipe) ToCloudGuardResponderRecipeOutputWithContext(ctx context.Context) CloudGuardResponderRecipeOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardResponderRecipeOutput)
}

func (i *CloudGuardResponderRecipe) ToCloudGuardResponderRecipePtrOutput() CloudGuardResponderRecipePtrOutput {
	return i.ToCloudGuardResponderRecipePtrOutputWithContext(context.Background())
}

func (i *CloudGuardResponderRecipe) ToCloudGuardResponderRecipePtrOutputWithContext(ctx context.Context) CloudGuardResponderRecipePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardResponderRecipePtrOutput)
}

type CloudGuardResponderRecipePtrInput interface {
	pulumi.Input

	ToCloudGuardResponderRecipePtrOutput() CloudGuardResponderRecipePtrOutput
	ToCloudGuardResponderRecipePtrOutputWithContext(ctx context.Context) CloudGuardResponderRecipePtrOutput
}

type cloudGuardResponderRecipePtrType CloudGuardResponderRecipeArgs

func (*cloudGuardResponderRecipePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CloudGuardResponderRecipe)(nil))
}

func (i *cloudGuardResponderRecipePtrType) ToCloudGuardResponderRecipePtrOutput() CloudGuardResponderRecipePtrOutput {
	return i.ToCloudGuardResponderRecipePtrOutputWithContext(context.Background())
}

func (i *cloudGuardResponderRecipePtrType) ToCloudGuardResponderRecipePtrOutputWithContext(ctx context.Context) CloudGuardResponderRecipePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardResponderRecipePtrOutput)
}

// CloudGuardResponderRecipeArrayInput is an input type that accepts CloudGuardResponderRecipeArray and CloudGuardResponderRecipeArrayOutput values.
// You can construct a concrete instance of `CloudGuardResponderRecipeArrayInput` via:
//
//          CloudGuardResponderRecipeArray{ CloudGuardResponderRecipeArgs{...} }
type CloudGuardResponderRecipeArrayInput interface {
	pulumi.Input

	ToCloudGuardResponderRecipeArrayOutput() CloudGuardResponderRecipeArrayOutput
	ToCloudGuardResponderRecipeArrayOutputWithContext(context.Context) CloudGuardResponderRecipeArrayOutput
}

type CloudGuardResponderRecipeArray []CloudGuardResponderRecipeInput

func (CloudGuardResponderRecipeArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CloudGuardResponderRecipe)(nil)).Elem()
}

func (i CloudGuardResponderRecipeArray) ToCloudGuardResponderRecipeArrayOutput() CloudGuardResponderRecipeArrayOutput {
	return i.ToCloudGuardResponderRecipeArrayOutputWithContext(context.Background())
}

func (i CloudGuardResponderRecipeArray) ToCloudGuardResponderRecipeArrayOutputWithContext(ctx context.Context) CloudGuardResponderRecipeArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardResponderRecipeArrayOutput)
}

// CloudGuardResponderRecipeMapInput is an input type that accepts CloudGuardResponderRecipeMap and CloudGuardResponderRecipeMapOutput values.
// You can construct a concrete instance of `CloudGuardResponderRecipeMapInput` via:
//
//          CloudGuardResponderRecipeMap{ "key": CloudGuardResponderRecipeArgs{...} }
type CloudGuardResponderRecipeMapInput interface {
	pulumi.Input

	ToCloudGuardResponderRecipeMapOutput() CloudGuardResponderRecipeMapOutput
	ToCloudGuardResponderRecipeMapOutputWithContext(context.Context) CloudGuardResponderRecipeMapOutput
}

type CloudGuardResponderRecipeMap map[string]CloudGuardResponderRecipeInput

func (CloudGuardResponderRecipeMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CloudGuardResponderRecipe)(nil)).Elem()
}

func (i CloudGuardResponderRecipeMap) ToCloudGuardResponderRecipeMapOutput() CloudGuardResponderRecipeMapOutput {
	return i.ToCloudGuardResponderRecipeMapOutputWithContext(context.Background())
}

func (i CloudGuardResponderRecipeMap) ToCloudGuardResponderRecipeMapOutputWithContext(ctx context.Context) CloudGuardResponderRecipeMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardResponderRecipeMapOutput)
}

type CloudGuardResponderRecipeOutput struct {
	*pulumi.OutputState
}

func (CloudGuardResponderRecipeOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CloudGuardResponderRecipe)(nil))
}

func (o CloudGuardResponderRecipeOutput) ToCloudGuardResponderRecipeOutput() CloudGuardResponderRecipeOutput {
	return o
}

func (o CloudGuardResponderRecipeOutput) ToCloudGuardResponderRecipeOutputWithContext(ctx context.Context) CloudGuardResponderRecipeOutput {
	return o
}

func (o CloudGuardResponderRecipeOutput) ToCloudGuardResponderRecipePtrOutput() CloudGuardResponderRecipePtrOutput {
	return o.ToCloudGuardResponderRecipePtrOutputWithContext(context.Background())
}

func (o CloudGuardResponderRecipeOutput) ToCloudGuardResponderRecipePtrOutputWithContext(ctx context.Context) CloudGuardResponderRecipePtrOutput {
	return o.ApplyT(func(v CloudGuardResponderRecipe) *CloudGuardResponderRecipe {
		return &v
	}).(CloudGuardResponderRecipePtrOutput)
}

type CloudGuardResponderRecipePtrOutput struct {
	*pulumi.OutputState
}

func (CloudGuardResponderRecipePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CloudGuardResponderRecipe)(nil))
}

func (o CloudGuardResponderRecipePtrOutput) ToCloudGuardResponderRecipePtrOutput() CloudGuardResponderRecipePtrOutput {
	return o
}

func (o CloudGuardResponderRecipePtrOutput) ToCloudGuardResponderRecipePtrOutputWithContext(ctx context.Context) CloudGuardResponderRecipePtrOutput {
	return o
}

type CloudGuardResponderRecipeArrayOutput struct{ *pulumi.OutputState }

func (CloudGuardResponderRecipeArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CloudGuardResponderRecipe)(nil))
}

func (o CloudGuardResponderRecipeArrayOutput) ToCloudGuardResponderRecipeArrayOutput() CloudGuardResponderRecipeArrayOutput {
	return o
}

func (o CloudGuardResponderRecipeArrayOutput) ToCloudGuardResponderRecipeArrayOutputWithContext(ctx context.Context) CloudGuardResponderRecipeArrayOutput {
	return o
}

func (o CloudGuardResponderRecipeArrayOutput) Index(i pulumi.IntInput) CloudGuardResponderRecipeOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CloudGuardResponderRecipe {
		return vs[0].([]CloudGuardResponderRecipe)[vs[1].(int)]
	}).(CloudGuardResponderRecipeOutput)
}

type CloudGuardResponderRecipeMapOutput struct{ *pulumi.OutputState }

func (CloudGuardResponderRecipeMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CloudGuardResponderRecipe)(nil))
}

func (o CloudGuardResponderRecipeMapOutput) ToCloudGuardResponderRecipeMapOutput() CloudGuardResponderRecipeMapOutput {
	return o
}

func (o CloudGuardResponderRecipeMapOutput) ToCloudGuardResponderRecipeMapOutputWithContext(ctx context.Context) CloudGuardResponderRecipeMapOutput {
	return o
}

func (o CloudGuardResponderRecipeMapOutput) MapIndex(k pulumi.StringInput) CloudGuardResponderRecipeOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CloudGuardResponderRecipe {
		return vs[0].(map[string]CloudGuardResponderRecipe)[vs[1].(string)]
	}).(CloudGuardResponderRecipeOutput)
}

func init() {
	pulumi.RegisterOutputType(CloudGuardResponderRecipeOutput{})
	pulumi.RegisterOutputType(CloudGuardResponderRecipePtrOutput{})
	pulumi.RegisterOutputType(CloudGuardResponderRecipeArrayOutput{})
	pulumi.RegisterOutputType(CloudGuardResponderRecipeMapOutput{})
}
