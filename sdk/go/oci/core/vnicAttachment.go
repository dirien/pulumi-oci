// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Vnic Attachment resource in Oracle Cloud Infrastructure Core service.
//
// Creates a secondary VNIC and attaches it to the specified instance.
// For more information about secondary VNICs, see
// [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
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
// 		_, err := core.NewVnicAttachment(ctx, "testVnicAttachment", &core.VnicAttachmentArgs{
// 			CreateVnicDetails: &core.VnicAttachmentCreateVnicDetailsArgs{
// 				AssignPrivateDnsRecord: pulumi.Any(_var.Vnic_attachment_create_vnic_details_assign_private_dns_record),
// 				AssignPublicIp:         pulumi.Any(_var.Vnic_attachment_create_vnic_details_assign_public_ip),
// 				DefinedTags:            pulumi.Any(_var.Vnic_attachment_create_vnic_details_defined_tags),
// 				DisplayName:            pulumi.Any(_var.Vnic_attachment_create_vnic_details_display_name),
// 				FreeformTags:           pulumi.Any(_var.Vnic_attachment_create_vnic_details_freeform_tags),
// 				HostnameLabel:          pulumi.Any(_var.Vnic_attachment_create_vnic_details_hostname_label),
// 				NsgIds:                 pulumi.Any(_var.Vnic_attachment_create_vnic_details_nsg_ids),
// 				PrivateIp:              pulumi.Any(_var.Vnic_attachment_create_vnic_details_private_ip),
// 				SkipSourceDestCheck:    pulumi.Any(_var.Vnic_attachment_create_vnic_details_skip_source_dest_check),
// 				SubnetId:               pulumi.Any(oci_core_subnet.Test_subnet.Id),
// 				VlanId:                 pulumi.Any(oci_core_vlan.Test_vlan.Id),
// 			},
// 			InstanceId:  pulumi.Any(oci_core_instance.Test_instance.Id),
// 			DisplayName: pulumi.Any(_var.Vnic_attachment_display_name),
// 			NicIndex:    pulumi.Any(_var.Vnic_attachment_nic_index),
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
// VnicAttachments can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:core/vnicAttachment:VnicAttachment test_vnic_attachment "id"
// ```
type VnicAttachment struct {
	pulumi.CustomResourceState

	// The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringOutput `pulumi:"availabilityDomain"`
	// The OCID of the compartment the VNIC attachment is in, which is the same compartment the instance is in.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
	CreateVnicDetails VnicAttachmentCreateVnicDetailsOutput `pulumi:"createVnicDetails"`
	// A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The OCID of the instance.
	InstanceId pulumi.StringOutput `pulumi:"instanceId"`
	// Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
	NicIndex pulumi.IntOutput `pulumi:"nicIndex"`
	// The current state of the VNIC attachment.
	State pulumi.StringOutput `pulumi:"state"`
	// The OCID of the subnet to create the VNIC in. When launching an instance, use this `subnetId` instead of the deprecated `subnetId` in [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/LaunchInstanceDetails). At least one of them is required; if you provide both, the values must match.
	SubnetId pulumi.StringOutput `pulumi:"subnetId"`
	// The date and time the VNIC attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// Provide this attribute only if you are an Oracle Cloud VMware Solution customer and creating a secondary VNIC in a VLAN. The value is the OCID of the VLAN. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
	VlanId pulumi.StringOutput `pulumi:"vlanId"`
	// The Oracle-assigned VLAN tag of the attached VNIC. Available after the attachment process is complete.
	VlanTag pulumi.IntOutput `pulumi:"vlanTag"`
	// The OCID of the VNIC. Available after the attachment process is complete.
	VnicId pulumi.StringOutput `pulumi:"vnicId"`
}

// NewVnicAttachment registers a new resource with the given unique name, arguments, and options.
func NewVnicAttachment(ctx *pulumi.Context,
	name string, args *VnicAttachmentArgs, opts ...pulumi.ResourceOption) (*VnicAttachment, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CreateVnicDetails == nil {
		return nil, errors.New("invalid value for required argument 'CreateVnicDetails'")
	}
	if args.InstanceId == nil {
		return nil, errors.New("invalid value for required argument 'InstanceId'")
	}
	var resource VnicAttachment
	err := ctx.RegisterResource("oci:core/vnicAttachment:VnicAttachment", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetVnicAttachment gets an existing VnicAttachment resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetVnicAttachment(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *VnicAttachmentState, opts ...pulumi.ResourceOption) (*VnicAttachment, error) {
	var resource VnicAttachment
	err := ctx.ReadResource("oci:core/vnicAttachment:VnicAttachment", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering VnicAttachment resources.
type vnicAttachmentState struct {
	// The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The OCID of the compartment the VNIC attachment is in, which is the same compartment the instance is in.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
	CreateVnicDetails *VnicAttachmentCreateVnicDetails `pulumi:"createVnicDetails"`
	// A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The OCID of the instance.
	InstanceId *string `pulumi:"instanceId"`
	// Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
	NicIndex *int `pulumi:"nicIndex"`
	// The current state of the VNIC attachment.
	State *string `pulumi:"state"`
	// The OCID of the subnet to create the VNIC in. When launching an instance, use this `subnetId` instead of the deprecated `subnetId` in [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/LaunchInstanceDetails). At least one of them is required; if you provide both, the values must match.
	SubnetId *string `pulumi:"subnetId"`
	// The date and time the VNIC attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// Provide this attribute only if you are an Oracle Cloud VMware Solution customer and creating a secondary VNIC in a VLAN. The value is the OCID of the VLAN. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
	VlanId *string `pulumi:"vlanId"`
	// The Oracle-assigned VLAN tag of the attached VNIC. Available after the attachment process is complete.
	VlanTag *int `pulumi:"vlanTag"`
	// The OCID of the VNIC. Available after the attachment process is complete.
	VnicId *string `pulumi:"vnicId"`
}

type VnicAttachmentState struct {
	// The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput
	// The OCID of the compartment the VNIC attachment is in, which is the same compartment the instance is in.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
	CreateVnicDetails VnicAttachmentCreateVnicDetailsPtrInput
	// A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// The OCID of the instance.
	InstanceId pulumi.StringPtrInput
	// Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
	NicIndex pulumi.IntPtrInput
	// The current state of the VNIC attachment.
	State pulumi.StringPtrInput
	// The OCID of the subnet to create the VNIC in. When launching an instance, use this `subnetId` instead of the deprecated `subnetId` in [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/LaunchInstanceDetails). At least one of them is required; if you provide both, the values must match.
	SubnetId pulumi.StringPtrInput
	// The date and time the VNIC attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// Provide this attribute only if you are an Oracle Cloud VMware Solution customer and creating a secondary VNIC in a VLAN. The value is the OCID of the VLAN. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
	VlanId pulumi.StringPtrInput
	// The Oracle-assigned VLAN tag of the attached VNIC. Available after the attachment process is complete.
	VlanTag pulumi.IntPtrInput
	// The OCID of the VNIC. Available after the attachment process is complete.
	VnicId pulumi.StringPtrInput
}

func (VnicAttachmentState) ElementType() reflect.Type {
	return reflect.TypeOf((*vnicAttachmentState)(nil)).Elem()
}

type vnicAttachmentArgs struct {
	// (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
	CreateVnicDetails VnicAttachmentCreateVnicDetails `pulumi:"createVnicDetails"`
	// A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The OCID of the instance.
	InstanceId string `pulumi:"instanceId"`
	// Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
	NicIndex *int `pulumi:"nicIndex"`
}

// The set of arguments for constructing a VnicAttachment resource.
type VnicAttachmentArgs struct {
	// (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
	CreateVnicDetails VnicAttachmentCreateVnicDetailsInput
	// A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// The OCID of the instance.
	InstanceId pulumi.StringInput
	// Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
	NicIndex pulumi.IntPtrInput
}

func (VnicAttachmentArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*vnicAttachmentArgs)(nil)).Elem()
}

type VnicAttachmentInput interface {
	pulumi.Input

	ToVnicAttachmentOutput() VnicAttachmentOutput
	ToVnicAttachmentOutputWithContext(ctx context.Context) VnicAttachmentOutput
}

func (*VnicAttachment) ElementType() reflect.Type {
	return reflect.TypeOf((*VnicAttachment)(nil))
}

func (i *VnicAttachment) ToVnicAttachmentOutput() VnicAttachmentOutput {
	return i.ToVnicAttachmentOutputWithContext(context.Background())
}

func (i *VnicAttachment) ToVnicAttachmentOutputWithContext(ctx context.Context) VnicAttachmentOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VnicAttachmentOutput)
}

func (i *VnicAttachment) ToVnicAttachmentPtrOutput() VnicAttachmentPtrOutput {
	return i.ToVnicAttachmentPtrOutputWithContext(context.Background())
}

func (i *VnicAttachment) ToVnicAttachmentPtrOutputWithContext(ctx context.Context) VnicAttachmentPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VnicAttachmentPtrOutput)
}

type VnicAttachmentPtrInput interface {
	pulumi.Input

	ToVnicAttachmentPtrOutput() VnicAttachmentPtrOutput
	ToVnicAttachmentPtrOutputWithContext(ctx context.Context) VnicAttachmentPtrOutput
}

type vnicAttachmentPtrType VnicAttachmentArgs

func (*vnicAttachmentPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**VnicAttachment)(nil))
}

func (i *vnicAttachmentPtrType) ToVnicAttachmentPtrOutput() VnicAttachmentPtrOutput {
	return i.ToVnicAttachmentPtrOutputWithContext(context.Background())
}

func (i *vnicAttachmentPtrType) ToVnicAttachmentPtrOutputWithContext(ctx context.Context) VnicAttachmentPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VnicAttachmentPtrOutput)
}

// VnicAttachmentArrayInput is an input type that accepts VnicAttachmentArray and VnicAttachmentArrayOutput values.
// You can construct a concrete instance of `VnicAttachmentArrayInput` via:
//
//          VnicAttachmentArray{ VnicAttachmentArgs{...} }
type VnicAttachmentArrayInput interface {
	pulumi.Input

	ToVnicAttachmentArrayOutput() VnicAttachmentArrayOutput
	ToVnicAttachmentArrayOutputWithContext(context.Context) VnicAttachmentArrayOutput
}

type VnicAttachmentArray []VnicAttachmentInput

func (VnicAttachmentArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*VnicAttachment)(nil)).Elem()
}

func (i VnicAttachmentArray) ToVnicAttachmentArrayOutput() VnicAttachmentArrayOutput {
	return i.ToVnicAttachmentArrayOutputWithContext(context.Background())
}

func (i VnicAttachmentArray) ToVnicAttachmentArrayOutputWithContext(ctx context.Context) VnicAttachmentArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VnicAttachmentArrayOutput)
}

// VnicAttachmentMapInput is an input type that accepts VnicAttachmentMap and VnicAttachmentMapOutput values.
// You can construct a concrete instance of `VnicAttachmentMapInput` via:
//
//          VnicAttachmentMap{ "key": VnicAttachmentArgs{...} }
type VnicAttachmentMapInput interface {
	pulumi.Input

	ToVnicAttachmentMapOutput() VnicAttachmentMapOutput
	ToVnicAttachmentMapOutputWithContext(context.Context) VnicAttachmentMapOutput
}

type VnicAttachmentMap map[string]VnicAttachmentInput

func (VnicAttachmentMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*VnicAttachment)(nil)).Elem()
}

func (i VnicAttachmentMap) ToVnicAttachmentMapOutput() VnicAttachmentMapOutput {
	return i.ToVnicAttachmentMapOutputWithContext(context.Background())
}

func (i VnicAttachmentMap) ToVnicAttachmentMapOutputWithContext(ctx context.Context) VnicAttachmentMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VnicAttachmentMapOutput)
}

type VnicAttachmentOutput struct {
	*pulumi.OutputState
}

func (VnicAttachmentOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*VnicAttachment)(nil))
}

func (o VnicAttachmentOutput) ToVnicAttachmentOutput() VnicAttachmentOutput {
	return o
}

func (o VnicAttachmentOutput) ToVnicAttachmentOutputWithContext(ctx context.Context) VnicAttachmentOutput {
	return o
}

func (o VnicAttachmentOutput) ToVnicAttachmentPtrOutput() VnicAttachmentPtrOutput {
	return o.ToVnicAttachmentPtrOutputWithContext(context.Background())
}

func (o VnicAttachmentOutput) ToVnicAttachmentPtrOutputWithContext(ctx context.Context) VnicAttachmentPtrOutput {
	return o.ApplyT(func(v VnicAttachment) *VnicAttachment {
		return &v
	}).(VnicAttachmentPtrOutput)
}

type VnicAttachmentPtrOutput struct {
	*pulumi.OutputState
}

func (VnicAttachmentPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**VnicAttachment)(nil))
}

func (o VnicAttachmentPtrOutput) ToVnicAttachmentPtrOutput() VnicAttachmentPtrOutput {
	return o
}

func (o VnicAttachmentPtrOutput) ToVnicAttachmentPtrOutputWithContext(ctx context.Context) VnicAttachmentPtrOutput {
	return o
}

type VnicAttachmentArrayOutput struct{ *pulumi.OutputState }

func (VnicAttachmentArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]VnicAttachment)(nil))
}

func (o VnicAttachmentArrayOutput) ToVnicAttachmentArrayOutput() VnicAttachmentArrayOutput {
	return o
}

func (o VnicAttachmentArrayOutput) ToVnicAttachmentArrayOutputWithContext(ctx context.Context) VnicAttachmentArrayOutput {
	return o
}

func (o VnicAttachmentArrayOutput) Index(i pulumi.IntInput) VnicAttachmentOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) VnicAttachment {
		return vs[0].([]VnicAttachment)[vs[1].(int)]
	}).(VnicAttachmentOutput)
}

type VnicAttachmentMapOutput struct{ *pulumi.OutputState }

func (VnicAttachmentMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]VnicAttachment)(nil))
}

func (o VnicAttachmentMapOutput) ToVnicAttachmentMapOutput() VnicAttachmentMapOutput {
	return o
}

func (o VnicAttachmentMapOutput) ToVnicAttachmentMapOutputWithContext(ctx context.Context) VnicAttachmentMapOutput {
	return o
}

func (o VnicAttachmentMapOutput) MapIndex(k pulumi.StringInput) VnicAttachmentOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) VnicAttachment {
		return vs[0].(map[string]VnicAttachment)[vs[1].(string)]
	}).(VnicAttachmentOutput)
}

func init() {
	pulumi.RegisterOutputType(VnicAttachmentOutput{})
	pulumi.RegisterOutputType(VnicAttachmentPtrOutput{})
	pulumi.RegisterOutputType(VnicAttachmentArrayOutput{})
	pulumi.RegisterOutputType(VnicAttachmentMapOutput{})
}
