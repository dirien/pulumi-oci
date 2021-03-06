// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Ipv6 resource in Oracle Cloud Infrastructure Core service.
//
// Creates an IPv6 for the specified VNIC.
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
// 		_, err := oci.NewCoreIpv6(ctx, "testIpv6", &oci.CoreIpv6Args{
// 			VnicId: pulumi.Any(oci_core_vnic_attachment.Test_vnic_attachment.Id),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			DisplayName: pulumi.Any(_var.Ipv6_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
// 			IpAddress: pulumi.Any(_var.Ipv6_ip_address),
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
// Ipv6 can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/coreIpv6:CoreIpv6 test_ipv6 "id"
// ```
type CoreIpv6 struct {
	pulumi.CustomResourceState

	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the IPv6. This is the same as the VNIC's compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// An IPv6 address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns an IPv6 address from the subnet. The subnet is the one that contains the VNIC you specify in `vnicId`.  Example: `2001:DB8::`
	IpAddress pulumi.StringOutput `pulumi:"ipAddress"`
	// The IPv6's current state.
	State pulumi.StringOutput `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the VNIC is in.
	SubnetId pulumi.StringOutput `pulumi:"subnetId"`
	// The date and time the IPv6 was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC to assign the IPv6 to. The IPv6 will be in the VNIC's subnet.
	VnicId pulumi.StringOutput `pulumi:"vnicId"`
}

// NewCoreIpv6 registers a new resource with the given unique name, arguments, and options.
func NewCoreIpv6(ctx *pulumi.Context,
	name string, args *CoreIpv6Args, opts ...pulumi.ResourceOption) (*CoreIpv6, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.VnicId == nil {
		return nil, errors.New("invalid value for required argument 'VnicId'")
	}
	var resource CoreIpv6
	err := ctx.RegisterResource("oci:index/coreIpv6:CoreIpv6", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCoreIpv6 gets an existing CoreIpv6 resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCoreIpv6(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CoreIpv6State, opts ...pulumi.ResourceOption) (*CoreIpv6, error) {
	var resource CoreIpv6
	err := ctx.ReadResource("oci:index/coreIpv6:CoreIpv6", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CoreIpv6 resources.
type coreIpv6State struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the IPv6. This is the same as the VNIC's compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// An IPv6 address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns an IPv6 address from the subnet. The subnet is the one that contains the VNIC you specify in `vnicId`.  Example: `2001:DB8::`
	IpAddress *string `pulumi:"ipAddress"`
	// The IPv6's current state.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the VNIC is in.
	SubnetId *string `pulumi:"subnetId"`
	// The date and time the IPv6 was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC to assign the IPv6 to. The IPv6 will be in the VNIC's subnet.
	VnicId *string `pulumi:"vnicId"`
}

type CoreIpv6State struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the IPv6. This is the same as the VNIC's compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// An IPv6 address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns an IPv6 address from the subnet. The subnet is the one that contains the VNIC you specify in `vnicId`.  Example: `2001:DB8::`
	IpAddress pulumi.StringPtrInput
	// The IPv6's current state.
	State pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the VNIC is in.
	SubnetId pulumi.StringPtrInput
	// The date and time the IPv6 was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC to assign the IPv6 to. The IPv6 will be in the VNIC's subnet.
	VnicId pulumi.StringPtrInput
}

func (CoreIpv6State) ElementType() reflect.Type {
	return reflect.TypeOf((*coreIpv6State)(nil)).Elem()
}

type coreIpv6Args struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// An IPv6 address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns an IPv6 address from the subnet. The subnet is the one that contains the VNIC you specify in `vnicId`.  Example: `2001:DB8::`
	IpAddress *string `pulumi:"ipAddress"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC to assign the IPv6 to. The IPv6 will be in the VNIC's subnet.
	VnicId string `pulumi:"vnicId"`
}

// The set of arguments for constructing a CoreIpv6 resource.
type CoreIpv6Args struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// An IPv6 address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns an IPv6 address from the subnet. The subnet is the one that contains the VNIC you specify in `vnicId`.  Example: `2001:DB8::`
	IpAddress pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC to assign the IPv6 to. The IPv6 will be in the VNIC's subnet.
	VnicId pulumi.StringInput
}

func (CoreIpv6Args) ElementType() reflect.Type {
	return reflect.TypeOf((*coreIpv6Args)(nil)).Elem()
}

type CoreIpv6Input interface {
	pulumi.Input

	ToCoreIpv6Output() CoreIpv6Output
	ToCoreIpv6OutputWithContext(ctx context.Context) CoreIpv6Output
}

func (*CoreIpv6) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreIpv6)(nil))
}

func (i *CoreIpv6) ToCoreIpv6Output() CoreIpv6Output {
	return i.ToCoreIpv6OutputWithContext(context.Background())
}

func (i *CoreIpv6) ToCoreIpv6OutputWithContext(ctx context.Context) CoreIpv6Output {
	return pulumi.ToOutputWithContext(ctx, i).(CoreIpv6Output)
}

func (i *CoreIpv6) ToCoreIpv6PtrOutput() CoreIpv6PtrOutput {
	return i.ToCoreIpv6PtrOutputWithContext(context.Background())
}

func (i *CoreIpv6) ToCoreIpv6PtrOutputWithContext(ctx context.Context) CoreIpv6PtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreIpv6PtrOutput)
}

type CoreIpv6PtrInput interface {
	pulumi.Input

	ToCoreIpv6PtrOutput() CoreIpv6PtrOutput
	ToCoreIpv6PtrOutputWithContext(ctx context.Context) CoreIpv6PtrOutput
}

type coreIpv6PtrType CoreIpv6Args

func (*coreIpv6PtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreIpv6)(nil))
}

func (i *coreIpv6PtrType) ToCoreIpv6PtrOutput() CoreIpv6PtrOutput {
	return i.ToCoreIpv6PtrOutputWithContext(context.Background())
}

func (i *coreIpv6PtrType) ToCoreIpv6PtrOutputWithContext(ctx context.Context) CoreIpv6PtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreIpv6PtrOutput)
}

// CoreIpv6ArrayInput is an input type that accepts CoreIpv6Array and CoreIpv6ArrayOutput values.
// You can construct a concrete instance of `CoreIpv6ArrayInput` via:
//
//          CoreIpv6Array{ CoreIpv6Args{...} }
type CoreIpv6ArrayInput interface {
	pulumi.Input

	ToCoreIpv6ArrayOutput() CoreIpv6ArrayOutput
	ToCoreIpv6ArrayOutputWithContext(context.Context) CoreIpv6ArrayOutput
}

type CoreIpv6Array []CoreIpv6Input

func (CoreIpv6Array) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CoreIpv6)(nil)).Elem()
}

func (i CoreIpv6Array) ToCoreIpv6ArrayOutput() CoreIpv6ArrayOutput {
	return i.ToCoreIpv6ArrayOutputWithContext(context.Background())
}

func (i CoreIpv6Array) ToCoreIpv6ArrayOutputWithContext(ctx context.Context) CoreIpv6ArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreIpv6ArrayOutput)
}

// CoreIpv6MapInput is an input type that accepts CoreIpv6Map and CoreIpv6MapOutput values.
// You can construct a concrete instance of `CoreIpv6MapInput` via:
//
//          CoreIpv6Map{ "key": CoreIpv6Args{...} }
type CoreIpv6MapInput interface {
	pulumi.Input

	ToCoreIpv6MapOutput() CoreIpv6MapOutput
	ToCoreIpv6MapOutputWithContext(context.Context) CoreIpv6MapOutput
}

type CoreIpv6Map map[string]CoreIpv6Input

func (CoreIpv6Map) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CoreIpv6)(nil)).Elem()
}

func (i CoreIpv6Map) ToCoreIpv6MapOutput() CoreIpv6MapOutput {
	return i.ToCoreIpv6MapOutputWithContext(context.Background())
}

func (i CoreIpv6Map) ToCoreIpv6MapOutputWithContext(ctx context.Context) CoreIpv6MapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreIpv6MapOutput)
}

type CoreIpv6Output struct {
	*pulumi.OutputState
}

func (CoreIpv6Output) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreIpv6)(nil))
}

func (o CoreIpv6Output) ToCoreIpv6Output() CoreIpv6Output {
	return o
}

func (o CoreIpv6Output) ToCoreIpv6OutputWithContext(ctx context.Context) CoreIpv6Output {
	return o
}

func (o CoreIpv6Output) ToCoreIpv6PtrOutput() CoreIpv6PtrOutput {
	return o.ToCoreIpv6PtrOutputWithContext(context.Background())
}

func (o CoreIpv6Output) ToCoreIpv6PtrOutputWithContext(ctx context.Context) CoreIpv6PtrOutput {
	return o.ApplyT(func(v CoreIpv6) *CoreIpv6 {
		return &v
	}).(CoreIpv6PtrOutput)
}

type CoreIpv6PtrOutput struct {
	*pulumi.OutputState
}

func (CoreIpv6PtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreIpv6)(nil))
}

func (o CoreIpv6PtrOutput) ToCoreIpv6PtrOutput() CoreIpv6PtrOutput {
	return o
}

func (o CoreIpv6PtrOutput) ToCoreIpv6PtrOutputWithContext(ctx context.Context) CoreIpv6PtrOutput {
	return o
}

type CoreIpv6ArrayOutput struct{ *pulumi.OutputState }

func (CoreIpv6ArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CoreIpv6)(nil))
}

func (o CoreIpv6ArrayOutput) ToCoreIpv6ArrayOutput() CoreIpv6ArrayOutput {
	return o
}

func (o CoreIpv6ArrayOutput) ToCoreIpv6ArrayOutputWithContext(ctx context.Context) CoreIpv6ArrayOutput {
	return o
}

func (o CoreIpv6ArrayOutput) Index(i pulumi.IntInput) CoreIpv6Output {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CoreIpv6 {
		return vs[0].([]CoreIpv6)[vs[1].(int)]
	}).(CoreIpv6Output)
}

type CoreIpv6MapOutput struct{ *pulumi.OutputState }

func (CoreIpv6MapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CoreIpv6)(nil))
}

func (o CoreIpv6MapOutput) ToCoreIpv6MapOutput() CoreIpv6MapOutput {
	return o
}

func (o CoreIpv6MapOutput) ToCoreIpv6MapOutputWithContext(ctx context.Context) CoreIpv6MapOutput {
	return o
}

func (o CoreIpv6MapOutput) MapIndex(k pulumi.StringInput) CoreIpv6Output {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CoreIpv6 {
		return vs[0].(map[string]CoreIpv6)[vs[1].(string)]
	}).(CoreIpv6Output)
}

func init() {
	pulumi.RegisterOutputType(CoreIpv6Output{})
	pulumi.RegisterOutputType(CoreIpv6PtrOutput{})
	pulumi.RegisterOutputType(CoreIpv6ArrayOutput{})
	pulumi.RegisterOutputType(CoreIpv6MapOutput{})
}
