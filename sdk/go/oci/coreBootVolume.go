// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Boot Volume resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new boot volume in the specified compartment from an existing boot volume or a boot volume backup.
// For general information about boot volumes, see [Boot Volumes](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/bootvolumes.htm).
// You may optionally specify a *display name* for the volume, which is simply a friendly name or
// description. It does not have to be unique, and you can change it. Avoid entering confidential information.
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
// 		_, err := oci.NewCoreBootVolume(ctx, "testBootVolume", &oci.CoreBootVolumeArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			SourceDetails: &CoreBootVolumeSourceDetailsArgs{
// 				Id:   pulumi.Any(_var.Boot_volume_source_details_id),
// 				Type: pulumi.Any(_var.Boot_volume_source_details_type),
// 			},
// 			AvailabilityDomain: pulumi.Any(_var.Boot_volume_availability_domain),
// 			BackupPolicyId:     pulumi.Any(data.Oci_core_volume_backup_policies.Test_volume_backup_policies.Volume_backup_policies[0].Id),
// 			BootVolumeReplicas: CoreBootVolumeBootVolumeReplicaArray{
// 				&CoreBootVolumeBootVolumeReplicaArgs{
// 					AvailabilityDomain: pulumi.Any(_var.Boot_volume_boot_volume_replicas_availability_domain),
// 					DisplayName:        pulumi.Any(_var.Boot_volume_boot_volume_replicas_display_name),
// 				},
// 			},
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			DisplayName: pulumi.Any(_var.Boot_volume_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
// 			IsAutoTuneEnabled:          pulumi.Any(_var.Boot_volume_is_auto_tune_enabled),
// 			KmsKeyId:                   pulumi.Any(oci_kms_key.Test_key.Id),
// 			SizeInGbs:                  pulumi.Any(_var.Boot_volume_size_in_gbs),
// 			VpusPerGb:                  pulumi.Any(_var.Boot_volume_vpus_per_gb),
// 			BootVolumeReplicasDeletion: pulumi.Bool(true),
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
// BootVolumes can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/coreBootVolume:CoreBootVolume test_boot_volume "id"
// ```
type CoreBootVolume struct {
	pulumi.CustomResourceState

	// The number of Volume Performance Units per GB that this boot volume is effectively tuned to when it's idle.
	AutoTunedVpusPerGb pulumi.StringOutput `pulumi:"autoTunedVpusPerGb"`
	// (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringOutput `pulumi:"availabilityDomain"`
	// If provided, specifies the ID of the boot volume backup policy to assign to the newly created boot volume. If omitted, no policy will be assigned.
	//
	// Deprecated: The 'backup_policy_id' field has been deprecated. Please use the 'oci_core_volume_backup_policy_assignment' resource instead.
	BackupPolicyId pulumi.StringOutput `pulumi:"backupPolicyId"`
	// (Updatable) The list of boot volume replicas to be enabled for this boot volume in the specified destination availability domains.
	BootVolumeReplicas CoreBootVolumeBootVolumeReplicaArrayOutput `pulumi:"bootVolumeReplicas"`
	// (updatable) The boolean value, if you have replicas and want to disable replicas set this argument to true and remove `bootVolumeReplicas` in representation at the same time. If you want to enable a new replicas, remove this argument and use `bootVolumeReplicas` again.
	BootVolumeReplicasDeletion pulumi.BoolPtrOutput `pulumi:"bootVolumeReplicasDeletion"`
	// (Updatable) The OCID of the compartment that contains the boot volume.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The image OCID used to create the boot volume.
	ImageId pulumi.StringOutput `pulumi:"imageId"`
	// (Updatable) Specifies whether the auto-tune performance is enabled for this boot volume.
	IsAutoTuneEnabled pulumi.BoolOutput `pulumi:"isAutoTuneEnabled"`
	// Specifies whether the boot volume's data has finished copying from the source boot volume or boot volume backup.
	IsHydrated pulumi.BoolOutput `pulumi:"isHydrated"`
	// (Updatable) The OCID of the Key Management key to assign as the master encryption key for the boot volume.
	KmsKeyId pulumi.StringOutput `pulumi:"kmsKeyId"`
	// (Updatable) The size of the volume in GBs.
	SizeInGbs pulumi.StringOutput `pulumi:"sizeInGbs"`
	// The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Please use `sizeInGbs`.
	SizeInMbs     pulumi.StringOutput               `pulumi:"sizeInMbs"`
	SourceDetails CoreBootVolumeSourceDetailsOutput `pulumi:"sourceDetails"`
	// The current state of a boot volume.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The date and time the boot volume was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The OCID of the source volume group.
	VolumeGroupId pulumi.StringOutput `pulumi:"volumeGroupId"`
	// (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Elastic Performance](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeelasticperformance.htm) for more information.
	VpusPerGb pulumi.StringOutput `pulumi:"vpusPerGb"`
}

// NewCoreBootVolume registers a new resource with the given unique name, arguments, and options.
func NewCoreBootVolume(ctx *pulumi.Context,
	name string, args *CoreBootVolumeArgs, opts ...pulumi.ResourceOption) (*CoreBootVolume, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AvailabilityDomain == nil {
		return nil, errors.New("invalid value for required argument 'AvailabilityDomain'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.SourceDetails == nil {
		return nil, errors.New("invalid value for required argument 'SourceDetails'")
	}
	var resource CoreBootVolume
	err := ctx.RegisterResource("oci:index/coreBootVolume:CoreBootVolume", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCoreBootVolume gets an existing CoreBootVolume resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCoreBootVolume(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CoreBootVolumeState, opts ...pulumi.ResourceOption) (*CoreBootVolume, error) {
	var resource CoreBootVolume
	err := ctx.ReadResource("oci:index/coreBootVolume:CoreBootVolume", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CoreBootVolume resources.
type coreBootVolumeState struct {
	// The number of Volume Performance Units per GB that this boot volume is effectively tuned to when it's idle.
	AutoTunedVpusPerGb *string `pulumi:"autoTunedVpusPerGb"`
	// (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// If provided, specifies the ID of the boot volume backup policy to assign to the newly created boot volume. If omitted, no policy will be assigned.
	//
	// Deprecated: The 'backup_policy_id' field has been deprecated. Please use the 'oci_core_volume_backup_policy_assignment' resource instead.
	BackupPolicyId *string `pulumi:"backupPolicyId"`
	// (Updatable) The list of boot volume replicas to be enabled for this boot volume in the specified destination availability domains.
	BootVolumeReplicas []CoreBootVolumeBootVolumeReplica `pulumi:"bootVolumeReplicas"`
	// (updatable) The boolean value, if you have replicas and want to disable replicas set this argument to true and remove `bootVolumeReplicas` in representation at the same time. If you want to enable a new replicas, remove this argument and use `bootVolumeReplicas` again.
	BootVolumeReplicasDeletion *bool `pulumi:"bootVolumeReplicasDeletion"`
	// (Updatable) The OCID of the compartment that contains the boot volume.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The image OCID used to create the boot volume.
	ImageId *string `pulumi:"imageId"`
	// (Updatable) Specifies whether the auto-tune performance is enabled for this boot volume.
	IsAutoTuneEnabled *bool `pulumi:"isAutoTuneEnabled"`
	// Specifies whether the boot volume's data has finished copying from the source boot volume or boot volume backup.
	IsHydrated *bool `pulumi:"isHydrated"`
	// (Updatable) The OCID of the Key Management key to assign as the master encryption key for the boot volume.
	KmsKeyId *string `pulumi:"kmsKeyId"`
	// (Updatable) The size of the volume in GBs.
	SizeInGbs *string `pulumi:"sizeInGbs"`
	// The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Please use `sizeInGbs`.
	SizeInMbs     *string                      `pulumi:"sizeInMbs"`
	SourceDetails *CoreBootVolumeSourceDetails `pulumi:"sourceDetails"`
	// The current state of a boot volume.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The date and time the boot volume was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The OCID of the source volume group.
	VolumeGroupId *string `pulumi:"volumeGroupId"`
	// (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Elastic Performance](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeelasticperformance.htm) for more information.
	VpusPerGb *string `pulumi:"vpusPerGb"`
}

type CoreBootVolumeState struct {
	// The number of Volume Performance Units per GB that this boot volume is effectively tuned to when it's idle.
	AutoTunedVpusPerGb pulumi.StringPtrInput
	// (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput
	// If provided, specifies the ID of the boot volume backup policy to assign to the newly created boot volume. If omitted, no policy will be assigned.
	//
	// Deprecated: The 'backup_policy_id' field has been deprecated. Please use the 'oci_core_volume_backup_policy_assignment' resource instead.
	BackupPolicyId pulumi.StringPtrInput
	// (Updatable) The list of boot volume replicas to be enabled for this boot volume in the specified destination availability domains.
	BootVolumeReplicas CoreBootVolumeBootVolumeReplicaArrayInput
	// (updatable) The boolean value, if you have replicas and want to disable replicas set this argument to true and remove `bootVolumeReplicas` in representation at the same time. If you want to enable a new replicas, remove this argument and use `bootVolumeReplicas` again.
	BootVolumeReplicasDeletion pulumi.BoolPtrInput
	// (Updatable) The OCID of the compartment that contains the boot volume.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The image OCID used to create the boot volume.
	ImageId pulumi.StringPtrInput
	// (Updatable) Specifies whether the auto-tune performance is enabled for this boot volume.
	IsAutoTuneEnabled pulumi.BoolPtrInput
	// Specifies whether the boot volume's data has finished copying from the source boot volume or boot volume backup.
	IsHydrated pulumi.BoolPtrInput
	// (Updatable) The OCID of the Key Management key to assign as the master encryption key for the boot volume.
	KmsKeyId pulumi.StringPtrInput
	// (Updatable) The size of the volume in GBs.
	SizeInGbs pulumi.StringPtrInput
	// The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Please use `sizeInGbs`.
	SizeInMbs     pulumi.StringPtrInput
	SourceDetails CoreBootVolumeSourceDetailsPtrInput
	// The current state of a boot volume.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	SystemTags pulumi.MapInput
	// The date and time the boot volume was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The OCID of the source volume group.
	VolumeGroupId pulumi.StringPtrInput
	// (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Elastic Performance](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeelasticperformance.htm) for more information.
	VpusPerGb pulumi.StringPtrInput
}

func (CoreBootVolumeState) ElementType() reflect.Type {
	return reflect.TypeOf((*coreBootVolumeState)(nil)).Elem()
}

type coreBootVolumeArgs struct {
	// (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// If provided, specifies the ID of the boot volume backup policy to assign to the newly created boot volume. If omitted, no policy will be assigned.
	//
	// Deprecated: The 'backup_policy_id' field has been deprecated. Please use the 'oci_core_volume_backup_policy_assignment' resource instead.
	BackupPolicyId *string `pulumi:"backupPolicyId"`
	// (Updatable) The list of boot volume replicas to be enabled for this boot volume in the specified destination availability domains.
	BootVolumeReplicas []CoreBootVolumeBootVolumeReplica `pulumi:"bootVolumeReplicas"`
	// (updatable) The boolean value, if you have replicas and want to disable replicas set this argument to true and remove `bootVolumeReplicas` in representation at the same time. If you want to enable a new replicas, remove this argument and use `bootVolumeReplicas` again.
	BootVolumeReplicasDeletion *bool `pulumi:"bootVolumeReplicasDeletion"`
	// (Updatable) The OCID of the compartment that contains the boot volume.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Specifies whether the auto-tune performance is enabled for this boot volume.
	IsAutoTuneEnabled *bool `pulumi:"isAutoTuneEnabled"`
	// (Updatable) The OCID of the Key Management key to assign as the master encryption key for the boot volume.
	KmsKeyId *string `pulumi:"kmsKeyId"`
	// (Updatable) The size of the volume in GBs.
	SizeInGbs     *string                     `pulumi:"sizeInGbs"`
	SourceDetails CoreBootVolumeSourceDetails `pulumi:"sourceDetails"`
	// (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Elastic Performance](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeelasticperformance.htm) for more information.
	VpusPerGb *string `pulumi:"vpusPerGb"`
}

// The set of arguments for constructing a CoreBootVolume resource.
type CoreBootVolumeArgs struct {
	// (Updatable) The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringInput
	// If provided, specifies the ID of the boot volume backup policy to assign to the newly created boot volume. If omitted, no policy will be assigned.
	//
	// Deprecated: The 'backup_policy_id' field has been deprecated. Please use the 'oci_core_volume_backup_policy_assignment' resource instead.
	BackupPolicyId pulumi.StringPtrInput
	// (Updatable) The list of boot volume replicas to be enabled for this boot volume in the specified destination availability domains.
	BootVolumeReplicas CoreBootVolumeBootVolumeReplicaArrayInput
	// (updatable) The boolean value, if you have replicas and want to disable replicas set this argument to true and remove `bootVolumeReplicas` in representation at the same time. If you want to enable a new replicas, remove this argument and use `bootVolumeReplicas` again.
	BootVolumeReplicasDeletion pulumi.BoolPtrInput
	// (Updatable) The OCID of the compartment that contains the boot volume.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Specifies whether the auto-tune performance is enabled for this boot volume.
	IsAutoTuneEnabled pulumi.BoolPtrInput
	// (Updatable) The OCID of the Key Management key to assign as the master encryption key for the boot volume.
	KmsKeyId pulumi.StringPtrInput
	// (Updatable) The size of the volume in GBs.
	SizeInGbs     pulumi.StringPtrInput
	SourceDetails CoreBootVolumeSourceDetailsInput
	// (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Elastic Performance](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeelasticperformance.htm) for more information.
	VpusPerGb pulumi.StringPtrInput
}

func (CoreBootVolumeArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*coreBootVolumeArgs)(nil)).Elem()
}

type CoreBootVolumeInput interface {
	pulumi.Input

	ToCoreBootVolumeOutput() CoreBootVolumeOutput
	ToCoreBootVolumeOutputWithContext(ctx context.Context) CoreBootVolumeOutput
}

func (*CoreBootVolume) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreBootVolume)(nil))
}

func (i *CoreBootVolume) ToCoreBootVolumeOutput() CoreBootVolumeOutput {
	return i.ToCoreBootVolumeOutputWithContext(context.Background())
}

func (i *CoreBootVolume) ToCoreBootVolumeOutputWithContext(ctx context.Context) CoreBootVolumeOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreBootVolumeOutput)
}

func (i *CoreBootVolume) ToCoreBootVolumePtrOutput() CoreBootVolumePtrOutput {
	return i.ToCoreBootVolumePtrOutputWithContext(context.Background())
}

func (i *CoreBootVolume) ToCoreBootVolumePtrOutputWithContext(ctx context.Context) CoreBootVolumePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreBootVolumePtrOutput)
}

type CoreBootVolumePtrInput interface {
	pulumi.Input

	ToCoreBootVolumePtrOutput() CoreBootVolumePtrOutput
	ToCoreBootVolumePtrOutputWithContext(ctx context.Context) CoreBootVolumePtrOutput
}

type coreBootVolumePtrType CoreBootVolumeArgs

func (*coreBootVolumePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreBootVolume)(nil))
}

func (i *coreBootVolumePtrType) ToCoreBootVolumePtrOutput() CoreBootVolumePtrOutput {
	return i.ToCoreBootVolumePtrOutputWithContext(context.Background())
}

func (i *coreBootVolumePtrType) ToCoreBootVolumePtrOutputWithContext(ctx context.Context) CoreBootVolumePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreBootVolumePtrOutput)
}

// CoreBootVolumeArrayInput is an input type that accepts CoreBootVolumeArray and CoreBootVolumeArrayOutput values.
// You can construct a concrete instance of `CoreBootVolumeArrayInput` via:
//
//          CoreBootVolumeArray{ CoreBootVolumeArgs{...} }
type CoreBootVolumeArrayInput interface {
	pulumi.Input

	ToCoreBootVolumeArrayOutput() CoreBootVolumeArrayOutput
	ToCoreBootVolumeArrayOutputWithContext(context.Context) CoreBootVolumeArrayOutput
}

type CoreBootVolumeArray []CoreBootVolumeInput

func (CoreBootVolumeArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CoreBootVolume)(nil)).Elem()
}

func (i CoreBootVolumeArray) ToCoreBootVolumeArrayOutput() CoreBootVolumeArrayOutput {
	return i.ToCoreBootVolumeArrayOutputWithContext(context.Background())
}

func (i CoreBootVolumeArray) ToCoreBootVolumeArrayOutputWithContext(ctx context.Context) CoreBootVolumeArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreBootVolumeArrayOutput)
}

// CoreBootVolumeMapInput is an input type that accepts CoreBootVolumeMap and CoreBootVolumeMapOutput values.
// You can construct a concrete instance of `CoreBootVolumeMapInput` via:
//
//          CoreBootVolumeMap{ "key": CoreBootVolumeArgs{...} }
type CoreBootVolumeMapInput interface {
	pulumi.Input

	ToCoreBootVolumeMapOutput() CoreBootVolumeMapOutput
	ToCoreBootVolumeMapOutputWithContext(context.Context) CoreBootVolumeMapOutput
}

type CoreBootVolumeMap map[string]CoreBootVolumeInput

func (CoreBootVolumeMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CoreBootVolume)(nil)).Elem()
}

func (i CoreBootVolumeMap) ToCoreBootVolumeMapOutput() CoreBootVolumeMapOutput {
	return i.ToCoreBootVolumeMapOutputWithContext(context.Background())
}

func (i CoreBootVolumeMap) ToCoreBootVolumeMapOutputWithContext(ctx context.Context) CoreBootVolumeMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreBootVolumeMapOutput)
}

type CoreBootVolumeOutput struct {
	*pulumi.OutputState
}

func (CoreBootVolumeOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreBootVolume)(nil))
}

func (o CoreBootVolumeOutput) ToCoreBootVolumeOutput() CoreBootVolumeOutput {
	return o
}

func (o CoreBootVolumeOutput) ToCoreBootVolumeOutputWithContext(ctx context.Context) CoreBootVolumeOutput {
	return o
}

func (o CoreBootVolumeOutput) ToCoreBootVolumePtrOutput() CoreBootVolumePtrOutput {
	return o.ToCoreBootVolumePtrOutputWithContext(context.Background())
}

func (o CoreBootVolumeOutput) ToCoreBootVolumePtrOutputWithContext(ctx context.Context) CoreBootVolumePtrOutput {
	return o.ApplyT(func(v CoreBootVolume) *CoreBootVolume {
		return &v
	}).(CoreBootVolumePtrOutput)
}

type CoreBootVolumePtrOutput struct {
	*pulumi.OutputState
}

func (CoreBootVolumePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreBootVolume)(nil))
}

func (o CoreBootVolumePtrOutput) ToCoreBootVolumePtrOutput() CoreBootVolumePtrOutput {
	return o
}

func (o CoreBootVolumePtrOutput) ToCoreBootVolumePtrOutputWithContext(ctx context.Context) CoreBootVolumePtrOutput {
	return o
}

type CoreBootVolumeArrayOutput struct{ *pulumi.OutputState }

func (CoreBootVolumeArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CoreBootVolume)(nil))
}

func (o CoreBootVolumeArrayOutput) ToCoreBootVolumeArrayOutput() CoreBootVolumeArrayOutput {
	return o
}

func (o CoreBootVolumeArrayOutput) ToCoreBootVolumeArrayOutputWithContext(ctx context.Context) CoreBootVolumeArrayOutput {
	return o
}

func (o CoreBootVolumeArrayOutput) Index(i pulumi.IntInput) CoreBootVolumeOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CoreBootVolume {
		return vs[0].([]CoreBootVolume)[vs[1].(int)]
	}).(CoreBootVolumeOutput)
}

type CoreBootVolumeMapOutput struct{ *pulumi.OutputState }

func (CoreBootVolumeMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CoreBootVolume)(nil))
}

func (o CoreBootVolumeMapOutput) ToCoreBootVolumeMapOutput() CoreBootVolumeMapOutput {
	return o
}

func (o CoreBootVolumeMapOutput) ToCoreBootVolumeMapOutputWithContext(ctx context.Context) CoreBootVolumeMapOutput {
	return o
}

func (o CoreBootVolumeMapOutput) MapIndex(k pulumi.StringInput) CoreBootVolumeOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CoreBootVolume {
		return vs[0].(map[string]CoreBootVolume)[vs[1].(string)]
	}).(CoreBootVolumeOutput)
}

func init() {
	pulumi.RegisterOutputType(CoreBootVolumeOutput{})
	pulumi.RegisterOutputType(CoreBootVolumePtrOutput{})
	pulumi.RegisterOutputType(CoreBootVolumeArrayOutput{})
	pulumi.RegisterOutputType(CoreBootVolumeMapOutput{})
}
