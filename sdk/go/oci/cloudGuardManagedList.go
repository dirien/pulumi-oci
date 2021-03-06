// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Managed List resource in Oracle Cloud Infrastructure Cloud Guard service.
//
// Creates a new ManagedList.
//
// ## Import
//
// ManagedLists can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/cloudGuardManagedList:CloudGuardManagedList test_managed_list "id"
// ```
type CloudGuardManagedList struct {
	pulumi.CustomResourceState

	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) ManagedList description
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) ManagedList display name
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// provider of the feed
	FeedProvider pulumi.StringOutput `pulumi:"feedProvider"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// If this list is editable or not
	IsEditable pulumi.BoolOutput `pulumi:"isEditable"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecyleDetails pulumi.StringOutput `pulumi:"lifecyleDetails"`
	// (Updatable) List of ManagedListItem
	ListItems pulumi.StringArrayOutput `pulumi:"listItems"`
	// type of the list
	ListType pulumi.StringOutput `pulumi:"listType"`
	// OCID of the Source ManagedList
	SourceManagedListId pulumi.StringOutput `pulumi:"sourceManagedListId"`
	// The current state of the resource.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The date and time the managed list was created. Format defined by RFC3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the managed list was updated. Format defined by RFC3339.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewCloudGuardManagedList registers a new resource with the given unique name, arguments, and options.
func NewCloudGuardManagedList(ctx *pulumi.Context,
	name string, args *CloudGuardManagedListArgs, opts ...pulumi.ResourceOption) (*CloudGuardManagedList, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	var resource CloudGuardManagedList
	err := ctx.RegisterResource("oci:index/cloudGuardManagedList:CloudGuardManagedList", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCloudGuardManagedList gets an existing CloudGuardManagedList resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCloudGuardManagedList(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CloudGuardManagedListState, opts ...pulumi.ResourceOption) (*CloudGuardManagedList, error) {
	var resource CloudGuardManagedList
	err := ctx.ReadResource("oci:index/cloudGuardManagedList:CloudGuardManagedList", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CloudGuardManagedList resources.
type cloudGuardManagedListState struct {
	// (Updatable) Compartment Identifier
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) ManagedList description
	Description *string `pulumi:"description"`
	// (Updatable) ManagedList display name
	DisplayName *string `pulumi:"displayName"`
	// provider of the feed
	FeedProvider *string `pulumi:"feedProvider"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// If this list is editable or not
	IsEditable *bool `pulumi:"isEditable"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecyleDetails *string `pulumi:"lifecyleDetails"`
	// (Updatable) List of ManagedListItem
	ListItems []string `pulumi:"listItems"`
	// type of the list
	ListType *string `pulumi:"listType"`
	// OCID of the Source ManagedList
	SourceManagedListId *string `pulumi:"sourceManagedListId"`
	// The current state of the resource.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The date and time the managed list was created. Format defined by RFC3339.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the managed list was updated. Format defined by RFC3339.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type CloudGuardManagedListState struct {
	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) ManagedList description
	Description pulumi.StringPtrInput
	// (Updatable) ManagedList display name
	DisplayName pulumi.StringPtrInput
	// provider of the feed
	FeedProvider pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// If this list is editable or not
	IsEditable pulumi.BoolPtrInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecyleDetails pulumi.StringPtrInput
	// (Updatable) List of ManagedListItem
	ListItems pulumi.StringArrayInput
	// type of the list
	ListType pulumi.StringPtrInput
	// OCID of the Source ManagedList
	SourceManagedListId pulumi.StringPtrInput
	// The current state of the resource.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The date and time the managed list was created. Format defined by RFC3339.
	TimeCreated pulumi.StringPtrInput
	// The date and time the managed list was updated. Format defined by RFC3339.
	TimeUpdated pulumi.StringPtrInput
}

func (CloudGuardManagedListState) ElementType() reflect.Type {
	return reflect.TypeOf((*cloudGuardManagedListState)(nil)).Elem()
}

type cloudGuardManagedListArgs struct {
	// (Updatable) Compartment Identifier
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) ManagedList description
	Description *string `pulumi:"description"`
	// (Updatable) ManagedList display name
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) List of ManagedListItem
	ListItems []string `pulumi:"listItems"`
	// type of the list
	ListType *string `pulumi:"listType"`
	// OCID of the Source ManagedList
	SourceManagedListId *string `pulumi:"sourceManagedListId"`
}

// The set of arguments for constructing a CloudGuardManagedList resource.
type CloudGuardManagedListArgs struct {
	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) ManagedList description
	Description pulumi.StringPtrInput
	// (Updatable) ManagedList display name
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) List of ManagedListItem
	ListItems pulumi.StringArrayInput
	// type of the list
	ListType pulumi.StringPtrInput
	// OCID of the Source ManagedList
	SourceManagedListId pulumi.StringPtrInput
}

func (CloudGuardManagedListArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*cloudGuardManagedListArgs)(nil)).Elem()
}

type CloudGuardManagedListInput interface {
	pulumi.Input

	ToCloudGuardManagedListOutput() CloudGuardManagedListOutput
	ToCloudGuardManagedListOutputWithContext(ctx context.Context) CloudGuardManagedListOutput
}

func (*CloudGuardManagedList) ElementType() reflect.Type {
	return reflect.TypeOf((*CloudGuardManagedList)(nil))
}

func (i *CloudGuardManagedList) ToCloudGuardManagedListOutput() CloudGuardManagedListOutput {
	return i.ToCloudGuardManagedListOutputWithContext(context.Background())
}

func (i *CloudGuardManagedList) ToCloudGuardManagedListOutputWithContext(ctx context.Context) CloudGuardManagedListOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardManagedListOutput)
}

func (i *CloudGuardManagedList) ToCloudGuardManagedListPtrOutput() CloudGuardManagedListPtrOutput {
	return i.ToCloudGuardManagedListPtrOutputWithContext(context.Background())
}

func (i *CloudGuardManagedList) ToCloudGuardManagedListPtrOutputWithContext(ctx context.Context) CloudGuardManagedListPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardManagedListPtrOutput)
}

type CloudGuardManagedListPtrInput interface {
	pulumi.Input

	ToCloudGuardManagedListPtrOutput() CloudGuardManagedListPtrOutput
	ToCloudGuardManagedListPtrOutputWithContext(ctx context.Context) CloudGuardManagedListPtrOutput
}

type cloudGuardManagedListPtrType CloudGuardManagedListArgs

func (*cloudGuardManagedListPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CloudGuardManagedList)(nil))
}

func (i *cloudGuardManagedListPtrType) ToCloudGuardManagedListPtrOutput() CloudGuardManagedListPtrOutput {
	return i.ToCloudGuardManagedListPtrOutputWithContext(context.Background())
}

func (i *cloudGuardManagedListPtrType) ToCloudGuardManagedListPtrOutputWithContext(ctx context.Context) CloudGuardManagedListPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardManagedListPtrOutput)
}

// CloudGuardManagedListArrayInput is an input type that accepts CloudGuardManagedListArray and CloudGuardManagedListArrayOutput values.
// You can construct a concrete instance of `CloudGuardManagedListArrayInput` via:
//
//          CloudGuardManagedListArray{ CloudGuardManagedListArgs{...} }
type CloudGuardManagedListArrayInput interface {
	pulumi.Input

	ToCloudGuardManagedListArrayOutput() CloudGuardManagedListArrayOutput
	ToCloudGuardManagedListArrayOutputWithContext(context.Context) CloudGuardManagedListArrayOutput
}

type CloudGuardManagedListArray []CloudGuardManagedListInput

func (CloudGuardManagedListArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CloudGuardManagedList)(nil)).Elem()
}

func (i CloudGuardManagedListArray) ToCloudGuardManagedListArrayOutput() CloudGuardManagedListArrayOutput {
	return i.ToCloudGuardManagedListArrayOutputWithContext(context.Background())
}

func (i CloudGuardManagedListArray) ToCloudGuardManagedListArrayOutputWithContext(ctx context.Context) CloudGuardManagedListArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardManagedListArrayOutput)
}

// CloudGuardManagedListMapInput is an input type that accepts CloudGuardManagedListMap and CloudGuardManagedListMapOutput values.
// You can construct a concrete instance of `CloudGuardManagedListMapInput` via:
//
//          CloudGuardManagedListMap{ "key": CloudGuardManagedListArgs{...} }
type CloudGuardManagedListMapInput interface {
	pulumi.Input

	ToCloudGuardManagedListMapOutput() CloudGuardManagedListMapOutput
	ToCloudGuardManagedListMapOutputWithContext(context.Context) CloudGuardManagedListMapOutput
}

type CloudGuardManagedListMap map[string]CloudGuardManagedListInput

func (CloudGuardManagedListMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CloudGuardManagedList)(nil)).Elem()
}

func (i CloudGuardManagedListMap) ToCloudGuardManagedListMapOutput() CloudGuardManagedListMapOutput {
	return i.ToCloudGuardManagedListMapOutputWithContext(context.Background())
}

func (i CloudGuardManagedListMap) ToCloudGuardManagedListMapOutputWithContext(ctx context.Context) CloudGuardManagedListMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardManagedListMapOutput)
}

type CloudGuardManagedListOutput struct {
	*pulumi.OutputState
}

func (CloudGuardManagedListOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CloudGuardManagedList)(nil))
}

func (o CloudGuardManagedListOutput) ToCloudGuardManagedListOutput() CloudGuardManagedListOutput {
	return o
}

func (o CloudGuardManagedListOutput) ToCloudGuardManagedListOutputWithContext(ctx context.Context) CloudGuardManagedListOutput {
	return o
}

func (o CloudGuardManagedListOutput) ToCloudGuardManagedListPtrOutput() CloudGuardManagedListPtrOutput {
	return o.ToCloudGuardManagedListPtrOutputWithContext(context.Background())
}

func (o CloudGuardManagedListOutput) ToCloudGuardManagedListPtrOutputWithContext(ctx context.Context) CloudGuardManagedListPtrOutput {
	return o.ApplyT(func(v CloudGuardManagedList) *CloudGuardManagedList {
		return &v
	}).(CloudGuardManagedListPtrOutput)
}

type CloudGuardManagedListPtrOutput struct {
	*pulumi.OutputState
}

func (CloudGuardManagedListPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CloudGuardManagedList)(nil))
}

func (o CloudGuardManagedListPtrOutput) ToCloudGuardManagedListPtrOutput() CloudGuardManagedListPtrOutput {
	return o
}

func (o CloudGuardManagedListPtrOutput) ToCloudGuardManagedListPtrOutputWithContext(ctx context.Context) CloudGuardManagedListPtrOutput {
	return o
}

type CloudGuardManagedListArrayOutput struct{ *pulumi.OutputState }

func (CloudGuardManagedListArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CloudGuardManagedList)(nil))
}

func (o CloudGuardManagedListArrayOutput) ToCloudGuardManagedListArrayOutput() CloudGuardManagedListArrayOutput {
	return o
}

func (o CloudGuardManagedListArrayOutput) ToCloudGuardManagedListArrayOutputWithContext(ctx context.Context) CloudGuardManagedListArrayOutput {
	return o
}

func (o CloudGuardManagedListArrayOutput) Index(i pulumi.IntInput) CloudGuardManagedListOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CloudGuardManagedList {
		return vs[0].([]CloudGuardManagedList)[vs[1].(int)]
	}).(CloudGuardManagedListOutput)
}

type CloudGuardManagedListMapOutput struct{ *pulumi.OutputState }

func (CloudGuardManagedListMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CloudGuardManagedList)(nil))
}

func (o CloudGuardManagedListMapOutput) ToCloudGuardManagedListMapOutput() CloudGuardManagedListMapOutput {
	return o
}

func (o CloudGuardManagedListMapOutput) ToCloudGuardManagedListMapOutputWithContext(ctx context.Context) CloudGuardManagedListMapOutput {
	return o
}

func (o CloudGuardManagedListMapOutput) MapIndex(k pulumi.StringInput) CloudGuardManagedListOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CloudGuardManagedList {
		return vs[0].(map[string]CloudGuardManagedList)[vs[1].(string)]
	}).(CloudGuardManagedListOutput)
}

func init() {
	pulumi.RegisterOutputType(CloudGuardManagedListOutput{})
	pulumi.RegisterOutputType(CloudGuardManagedListPtrOutput{})
	pulumi.RegisterOutputType(CloudGuardManagedListArrayOutput{})
	pulumi.RegisterOutputType(CloudGuardManagedListMapOutput{})
}
