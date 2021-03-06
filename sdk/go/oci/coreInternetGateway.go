// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Internet Gateway resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new internet gateway for the specified VCN. For more information, see
// [Access to the Internet](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingIGs.htm).
//
// For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want the Internet
// Gateway to reside. Notice that the internet gateway doesn't have to be in the same compartment as the VCN or
// other Networking Service components. If you're not sure which compartment to use, put the Internet
// Gateway in the same compartment with the VCN. For more information about compartments and access control, see
// [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
//
// You may optionally specify a *display name* for the internet gateway, otherwise a default is provided. It
// does not have to be unique, and you can change it. Avoid entering confidential information.
//
// For traffic to flow between a subnet and an internet gateway, you must create a route rule accordingly in
// the subnet's route table (for example, 0.0.0.0/0 > internet gateway). See
// [UpdateRouteTable](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/RouteTable/UpdateRouteTable).
//
// You must specify whether the internet gateway is enabled when you create it. If it's disabled, that means no
// traffic will flow to/from the internet even if there's a route rule that enables that traffic. You can later
// use [UpdateInternetGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/InternetGateway/UpdateInternetGateway) to easily disable/enable
// the gateway without changing the route rule.
//
// ## Import
//
// InternetGateways can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/coreInternetGateway:CoreInternetGateway test_internet_gateway "id"
// ```
type CoreInternetGateway struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment to contain the internet gateway.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Whether the gateway is enabled upon creation.
	Enabled pulumi.BoolPtrOutput `pulumi:"enabled"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The internet gateway's current state.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the internet gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The OCID of the VCN the internet gateway is attached to.
	VcnId pulumi.StringOutput `pulumi:"vcnId"`
}

// NewCoreInternetGateway registers a new resource with the given unique name, arguments, and options.
func NewCoreInternetGateway(ctx *pulumi.Context,
	name string, args *CoreInternetGatewayArgs, opts ...pulumi.ResourceOption) (*CoreInternetGateway, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.VcnId == nil {
		return nil, errors.New("invalid value for required argument 'VcnId'")
	}
	var resource CoreInternetGateway
	err := ctx.RegisterResource("oci:index/coreInternetGateway:CoreInternetGateway", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCoreInternetGateway gets an existing CoreInternetGateway resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCoreInternetGateway(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CoreInternetGatewayState, opts ...pulumi.ResourceOption) (*CoreInternetGateway, error) {
	var resource CoreInternetGateway
	err := ctx.ReadResource("oci:index/coreInternetGateway:CoreInternetGateway", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CoreInternetGateway resources.
type coreInternetGatewayState struct {
	// (Updatable) The OCID of the compartment to contain the internet gateway.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Whether the gateway is enabled upon creation.
	Enabled *bool `pulumi:"enabled"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The internet gateway's current state.
	State *string `pulumi:"state"`
	// The date and time the internet gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The OCID of the VCN the internet gateway is attached to.
	VcnId *string `pulumi:"vcnId"`
}

type CoreInternetGatewayState struct {
	// (Updatable) The OCID of the compartment to contain the internet gateway.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Whether the gateway is enabled upon creation.
	Enabled pulumi.BoolPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The internet gateway's current state.
	State pulumi.StringPtrInput
	// The date and time the internet gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The OCID of the VCN the internet gateway is attached to.
	VcnId pulumi.StringPtrInput
}

func (CoreInternetGatewayState) ElementType() reflect.Type {
	return reflect.TypeOf((*coreInternetGatewayState)(nil)).Elem()
}

type coreInternetGatewayArgs struct {
	// (Updatable) The OCID of the compartment to contain the internet gateway.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Whether the gateway is enabled upon creation.
	Enabled *bool `pulumi:"enabled"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the VCN the internet gateway is attached to.
	VcnId string `pulumi:"vcnId"`
}

// The set of arguments for constructing a CoreInternetGateway resource.
type CoreInternetGatewayArgs struct {
	// (Updatable) The OCID of the compartment to contain the internet gateway.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Whether the gateway is enabled upon creation.
	Enabled pulumi.BoolPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The OCID of the VCN the internet gateway is attached to.
	VcnId pulumi.StringInput
}

func (CoreInternetGatewayArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*coreInternetGatewayArgs)(nil)).Elem()
}

type CoreInternetGatewayInput interface {
	pulumi.Input

	ToCoreInternetGatewayOutput() CoreInternetGatewayOutput
	ToCoreInternetGatewayOutputWithContext(ctx context.Context) CoreInternetGatewayOutput
}

func (*CoreInternetGateway) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreInternetGateway)(nil))
}

func (i *CoreInternetGateway) ToCoreInternetGatewayOutput() CoreInternetGatewayOutput {
	return i.ToCoreInternetGatewayOutputWithContext(context.Background())
}

func (i *CoreInternetGateway) ToCoreInternetGatewayOutputWithContext(ctx context.Context) CoreInternetGatewayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreInternetGatewayOutput)
}

func (i *CoreInternetGateway) ToCoreInternetGatewayPtrOutput() CoreInternetGatewayPtrOutput {
	return i.ToCoreInternetGatewayPtrOutputWithContext(context.Background())
}

func (i *CoreInternetGateway) ToCoreInternetGatewayPtrOutputWithContext(ctx context.Context) CoreInternetGatewayPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreInternetGatewayPtrOutput)
}

type CoreInternetGatewayPtrInput interface {
	pulumi.Input

	ToCoreInternetGatewayPtrOutput() CoreInternetGatewayPtrOutput
	ToCoreInternetGatewayPtrOutputWithContext(ctx context.Context) CoreInternetGatewayPtrOutput
}

type coreInternetGatewayPtrType CoreInternetGatewayArgs

func (*coreInternetGatewayPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreInternetGateway)(nil))
}

func (i *coreInternetGatewayPtrType) ToCoreInternetGatewayPtrOutput() CoreInternetGatewayPtrOutput {
	return i.ToCoreInternetGatewayPtrOutputWithContext(context.Background())
}

func (i *coreInternetGatewayPtrType) ToCoreInternetGatewayPtrOutputWithContext(ctx context.Context) CoreInternetGatewayPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreInternetGatewayPtrOutput)
}

// CoreInternetGatewayArrayInput is an input type that accepts CoreInternetGatewayArray and CoreInternetGatewayArrayOutput values.
// You can construct a concrete instance of `CoreInternetGatewayArrayInput` via:
//
//          CoreInternetGatewayArray{ CoreInternetGatewayArgs{...} }
type CoreInternetGatewayArrayInput interface {
	pulumi.Input

	ToCoreInternetGatewayArrayOutput() CoreInternetGatewayArrayOutput
	ToCoreInternetGatewayArrayOutputWithContext(context.Context) CoreInternetGatewayArrayOutput
}

type CoreInternetGatewayArray []CoreInternetGatewayInput

func (CoreInternetGatewayArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CoreInternetGateway)(nil)).Elem()
}

func (i CoreInternetGatewayArray) ToCoreInternetGatewayArrayOutput() CoreInternetGatewayArrayOutput {
	return i.ToCoreInternetGatewayArrayOutputWithContext(context.Background())
}

func (i CoreInternetGatewayArray) ToCoreInternetGatewayArrayOutputWithContext(ctx context.Context) CoreInternetGatewayArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreInternetGatewayArrayOutput)
}

// CoreInternetGatewayMapInput is an input type that accepts CoreInternetGatewayMap and CoreInternetGatewayMapOutput values.
// You can construct a concrete instance of `CoreInternetGatewayMapInput` via:
//
//          CoreInternetGatewayMap{ "key": CoreInternetGatewayArgs{...} }
type CoreInternetGatewayMapInput interface {
	pulumi.Input

	ToCoreInternetGatewayMapOutput() CoreInternetGatewayMapOutput
	ToCoreInternetGatewayMapOutputWithContext(context.Context) CoreInternetGatewayMapOutput
}

type CoreInternetGatewayMap map[string]CoreInternetGatewayInput

func (CoreInternetGatewayMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CoreInternetGateway)(nil)).Elem()
}

func (i CoreInternetGatewayMap) ToCoreInternetGatewayMapOutput() CoreInternetGatewayMapOutput {
	return i.ToCoreInternetGatewayMapOutputWithContext(context.Background())
}

func (i CoreInternetGatewayMap) ToCoreInternetGatewayMapOutputWithContext(ctx context.Context) CoreInternetGatewayMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreInternetGatewayMapOutput)
}

type CoreInternetGatewayOutput struct {
	*pulumi.OutputState
}

func (CoreInternetGatewayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreInternetGateway)(nil))
}

func (o CoreInternetGatewayOutput) ToCoreInternetGatewayOutput() CoreInternetGatewayOutput {
	return o
}

func (o CoreInternetGatewayOutput) ToCoreInternetGatewayOutputWithContext(ctx context.Context) CoreInternetGatewayOutput {
	return o
}

func (o CoreInternetGatewayOutput) ToCoreInternetGatewayPtrOutput() CoreInternetGatewayPtrOutput {
	return o.ToCoreInternetGatewayPtrOutputWithContext(context.Background())
}

func (o CoreInternetGatewayOutput) ToCoreInternetGatewayPtrOutputWithContext(ctx context.Context) CoreInternetGatewayPtrOutput {
	return o.ApplyT(func(v CoreInternetGateway) *CoreInternetGateway {
		return &v
	}).(CoreInternetGatewayPtrOutput)
}

type CoreInternetGatewayPtrOutput struct {
	*pulumi.OutputState
}

func (CoreInternetGatewayPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreInternetGateway)(nil))
}

func (o CoreInternetGatewayPtrOutput) ToCoreInternetGatewayPtrOutput() CoreInternetGatewayPtrOutput {
	return o
}

func (o CoreInternetGatewayPtrOutput) ToCoreInternetGatewayPtrOutputWithContext(ctx context.Context) CoreInternetGatewayPtrOutput {
	return o
}

type CoreInternetGatewayArrayOutput struct{ *pulumi.OutputState }

func (CoreInternetGatewayArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CoreInternetGateway)(nil))
}

func (o CoreInternetGatewayArrayOutput) ToCoreInternetGatewayArrayOutput() CoreInternetGatewayArrayOutput {
	return o
}

func (o CoreInternetGatewayArrayOutput) ToCoreInternetGatewayArrayOutputWithContext(ctx context.Context) CoreInternetGatewayArrayOutput {
	return o
}

func (o CoreInternetGatewayArrayOutput) Index(i pulumi.IntInput) CoreInternetGatewayOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CoreInternetGateway {
		return vs[0].([]CoreInternetGateway)[vs[1].(int)]
	}).(CoreInternetGatewayOutput)
}

type CoreInternetGatewayMapOutput struct{ *pulumi.OutputState }

func (CoreInternetGatewayMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CoreInternetGateway)(nil))
}

func (o CoreInternetGatewayMapOutput) ToCoreInternetGatewayMapOutput() CoreInternetGatewayMapOutput {
	return o
}

func (o CoreInternetGatewayMapOutput) ToCoreInternetGatewayMapOutputWithContext(ctx context.Context) CoreInternetGatewayMapOutput {
	return o
}

func (o CoreInternetGatewayMapOutput) MapIndex(k pulumi.StringInput) CoreInternetGatewayOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CoreInternetGateway {
		return vs[0].(map[string]CoreInternetGateway)[vs[1].(string)]
	}).(CoreInternetGatewayOutput)
}

func init() {
	pulumi.RegisterOutputType(CoreInternetGatewayOutput{})
	pulumi.RegisterOutputType(CoreInternetGatewayPtrOutput{})
	pulumi.RegisterOutputType(CoreInternetGatewayArrayOutput{})
	pulumi.RegisterOutputType(CoreInternetGatewayMapOutput{})
}
