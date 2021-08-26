// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Cross Connect Group resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new cross-connect group to use with Oracle Cloud Infrastructure
// FastConnect. For more information, see
// [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
//
// For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the
// compartment where you want the cross-connect group to reside. If you're
// not sure which compartment to use, put the cross-connect group in the
// same compartment with your VCN. For more information about
// compartments and access control, see
// [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
// For information about OCIDs, see
// [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
//
// You may optionally specify a *display name* for the cross-connect group.
// It does not have to be unique, and you can change it. Avoid entering confidential information.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/core"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := core.NewCrossConnectGroup(ctx, "testCrossConnectGroup", &core.CrossConnectGroupArgs{
// 			CompartmentId:         pulumi.Any(_var.Compartment_id),
// 			CustomerReferenceName: pulumi.Any(_var.Cross_connect_group_customer_reference_name),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			DisplayName: pulumi.Any(_var.Cross_connect_group_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
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
// CrossConnectGroups can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:core/crossConnectGroup:CrossConnectGroup test_cross_connect_group "id"
// ```
type CrossConnectGroup struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment to contain the cross-connect group.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) A reference name or identifier for the physical fiber connection that this cross-connect group uses.
	CustomerReferenceName pulumi.StringOutput `pulumi:"customerReferenceName"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The cross-connect group's current state.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the cross-connect group was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewCrossConnectGroup registers a new resource with the given unique name, arguments, and options.
func NewCrossConnectGroup(ctx *pulumi.Context,
	name string, args *CrossConnectGroupArgs, opts ...pulumi.ResourceOption) (*CrossConnectGroup, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	var resource CrossConnectGroup
	err := ctx.RegisterResource("oci:core/crossConnectGroup:CrossConnectGroup", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCrossConnectGroup gets an existing CrossConnectGroup resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCrossConnectGroup(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CrossConnectGroupState, opts ...pulumi.ResourceOption) (*CrossConnectGroup, error) {
	var resource CrossConnectGroup
	err := ctx.ReadResource("oci:core/crossConnectGroup:CrossConnectGroup", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CrossConnectGroup resources.
type crossConnectGroupState struct {
	// (Updatable) The OCID of the compartment to contain the cross-connect group.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) A reference name or identifier for the physical fiber connection that this cross-connect group uses.
	CustomerReferenceName *string `pulumi:"customerReferenceName"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The cross-connect group's current state.
	State *string `pulumi:"state"`
	// The date and time the cross-connect group was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type CrossConnectGroupState struct {
	// (Updatable) The OCID of the compartment to contain the cross-connect group.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) A reference name or identifier for the physical fiber connection that this cross-connect group uses.
	CustomerReferenceName pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The cross-connect group's current state.
	State pulumi.StringPtrInput
	// The date and time the cross-connect group was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (CrossConnectGroupState) ElementType() reflect.Type {
	return reflect.TypeOf((*crossConnectGroupState)(nil)).Elem()
}

type crossConnectGroupArgs struct {
	// (Updatable) The OCID of the compartment to contain the cross-connect group.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) A reference name or identifier for the physical fiber connection that this cross-connect group uses.
	CustomerReferenceName *string `pulumi:"customerReferenceName"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
}

// The set of arguments for constructing a CrossConnectGroup resource.
type CrossConnectGroupArgs struct {
	// (Updatable) The OCID of the compartment to contain the cross-connect group.
	CompartmentId pulumi.StringInput
	// (Updatable) A reference name or identifier for the physical fiber connection that this cross-connect group uses.
	CustomerReferenceName pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
}

func (CrossConnectGroupArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*crossConnectGroupArgs)(nil)).Elem()
}

type CrossConnectGroupInput interface {
	pulumi.Input

	ToCrossConnectGroupOutput() CrossConnectGroupOutput
	ToCrossConnectGroupOutputWithContext(ctx context.Context) CrossConnectGroupOutput
}

func (*CrossConnectGroup) ElementType() reflect.Type {
	return reflect.TypeOf((*CrossConnectGroup)(nil))
}

func (i *CrossConnectGroup) ToCrossConnectGroupOutput() CrossConnectGroupOutput {
	return i.ToCrossConnectGroupOutputWithContext(context.Background())
}

func (i *CrossConnectGroup) ToCrossConnectGroupOutputWithContext(ctx context.Context) CrossConnectGroupOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CrossConnectGroupOutput)
}

func (i *CrossConnectGroup) ToCrossConnectGroupPtrOutput() CrossConnectGroupPtrOutput {
	return i.ToCrossConnectGroupPtrOutputWithContext(context.Background())
}

func (i *CrossConnectGroup) ToCrossConnectGroupPtrOutputWithContext(ctx context.Context) CrossConnectGroupPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CrossConnectGroupPtrOutput)
}

type CrossConnectGroupPtrInput interface {
	pulumi.Input

	ToCrossConnectGroupPtrOutput() CrossConnectGroupPtrOutput
	ToCrossConnectGroupPtrOutputWithContext(ctx context.Context) CrossConnectGroupPtrOutput
}

type crossConnectGroupPtrType CrossConnectGroupArgs

func (*crossConnectGroupPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CrossConnectGroup)(nil))
}

func (i *crossConnectGroupPtrType) ToCrossConnectGroupPtrOutput() CrossConnectGroupPtrOutput {
	return i.ToCrossConnectGroupPtrOutputWithContext(context.Background())
}

func (i *crossConnectGroupPtrType) ToCrossConnectGroupPtrOutputWithContext(ctx context.Context) CrossConnectGroupPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CrossConnectGroupPtrOutput)
}

// CrossConnectGroupArrayInput is an input type that accepts CrossConnectGroupArray and CrossConnectGroupArrayOutput values.
// You can construct a concrete instance of `CrossConnectGroupArrayInput` via:
//
//          CrossConnectGroupArray{ CrossConnectGroupArgs{...} }
type CrossConnectGroupArrayInput interface {
	pulumi.Input

	ToCrossConnectGroupArrayOutput() CrossConnectGroupArrayOutput
	ToCrossConnectGroupArrayOutputWithContext(context.Context) CrossConnectGroupArrayOutput
}

type CrossConnectGroupArray []CrossConnectGroupInput

func (CrossConnectGroupArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CrossConnectGroup)(nil)).Elem()
}

func (i CrossConnectGroupArray) ToCrossConnectGroupArrayOutput() CrossConnectGroupArrayOutput {
	return i.ToCrossConnectGroupArrayOutputWithContext(context.Background())
}

func (i CrossConnectGroupArray) ToCrossConnectGroupArrayOutputWithContext(ctx context.Context) CrossConnectGroupArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CrossConnectGroupArrayOutput)
}

// CrossConnectGroupMapInput is an input type that accepts CrossConnectGroupMap and CrossConnectGroupMapOutput values.
// You can construct a concrete instance of `CrossConnectGroupMapInput` via:
//
//          CrossConnectGroupMap{ "key": CrossConnectGroupArgs{...} }
type CrossConnectGroupMapInput interface {
	pulumi.Input

	ToCrossConnectGroupMapOutput() CrossConnectGroupMapOutput
	ToCrossConnectGroupMapOutputWithContext(context.Context) CrossConnectGroupMapOutput
}

type CrossConnectGroupMap map[string]CrossConnectGroupInput

func (CrossConnectGroupMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CrossConnectGroup)(nil)).Elem()
}

func (i CrossConnectGroupMap) ToCrossConnectGroupMapOutput() CrossConnectGroupMapOutput {
	return i.ToCrossConnectGroupMapOutputWithContext(context.Background())
}

func (i CrossConnectGroupMap) ToCrossConnectGroupMapOutputWithContext(ctx context.Context) CrossConnectGroupMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CrossConnectGroupMapOutput)
}

type CrossConnectGroupOutput struct {
	*pulumi.OutputState
}

func (CrossConnectGroupOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CrossConnectGroup)(nil))
}

func (o CrossConnectGroupOutput) ToCrossConnectGroupOutput() CrossConnectGroupOutput {
	return o
}

func (o CrossConnectGroupOutput) ToCrossConnectGroupOutputWithContext(ctx context.Context) CrossConnectGroupOutput {
	return o
}

func (o CrossConnectGroupOutput) ToCrossConnectGroupPtrOutput() CrossConnectGroupPtrOutput {
	return o.ToCrossConnectGroupPtrOutputWithContext(context.Background())
}

func (o CrossConnectGroupOutput) ToCrossConnectGroupPtrOutputWithContext(ctx context.Context) CrossConnectGroupPtrOutput {
	return o.ApplyT(func(v CrossConnectGroup) *CrossConnectGroup {
		return &v
	}).(CrossConnectGroupPtrOutput)
}

type CrossConnectGroupPtrOutput struct {
	*pulumi.OutputState
}

func (CrossConnectGroupPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CrossConnectGroup)(nil))
}

func (o CrossConnectGroupPtrOutput) ToCrossConnectGroupPtrOutput() CrossConnectGroupPtrOutput {
	return o
}

func (o CrossConnectGroupPtrOutput) ToCrossConnectGroupPtrOutputWithContext(ctx context.Context) CrossConnectGroupPtrOutput {
	return o
}

type CrossConnectGroupArrayOutput struct{ *pulumi.OutputState }

func (CrossConnectGroupArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CrossConnectGroup)(nil))
}

func (o CrossConnectGroupArrayOutput) ToCrossConnectGroupArrayOutput() CrossConnectGroupArrayOutput {
	return o
}

func (o CrossConnectGroupArrayOutput) ToCrossConnectGroupArrayOutputWithContext(ctx context.Context) CrossConnectGroupArrayOutput {
	return o
}

func (o CrossConnectGroupArrayOutput) Index(i pulumi.IntInput) CrossConnectGroupOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CrossConnectGroup {
		return vs[0].([]CrossConnectGroup)[vs[1].(int)]
	}).(CrossConnectGroupOutput)
}

type CrossConnectGroupMapOutput struct{ *pulumi.OutputState }

func (CrossConnectGroupMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CrossConnectGroup)(nil))
}

func (o CrossConnectGroupMapOutput) ToCrossConnectGroupMapOutput() CrossConnectGroupMapOutput {
	return o
}

func (o CrossConnectGroupMapOutput) ToCrossConnectGroupMapOutputWithContext(ctx context.Context) CrossConnectGroupMapOutput {
	return o
}

func (o CrossConnectGroupMapOutput) MapIndex(k pulumi.StringInput) CrossConnectGroupOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CrossConnectGroup {
		return vs[0].(map[string]CrossConnectGroup)[vs[1].(string)]
	}).(CrossConnectGroupOutput)
}

func init() {
	pulumi.RegisterOutputType(CrossConnectGroupOutput{})
	pulumi.RegisterOutputType(CrossConnectGroupPtrOutput{})
	pulumi.RegisterOutputType(CrossConnectGroupArrayOutput{})
	pulumi.RegisterOutputType(CrossConnectGroupMapOutput{})
}