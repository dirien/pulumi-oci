// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Boot Volume Backup resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new boot volume backup of the specified boot volume. For general information about boot volume backups,
// see [Overview of Boot Volume Backups](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/bootvolumebackups.htm)
//
// When the request is received, the backup object is in a REQUEST_RECEIVED state.
// When the data is imaged, it goes into a CREATING state.
// After the backup is fully uploaded to the cloud, it goes into an AVAILABLE state.
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
// 		_, err := core.NewBootVolumeBackup(ctx, "testBootVolumeBackup", &core.BootVolumeBackupArgs{
// 			BootVolumeId: pulumi.Any(oci_core_boot_volume.Test_boot_volume.Id),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			DisplayName: pulumi.Any(_var.Boot_volume_backup_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
// 			Type: pulumi.Any(_var.Boot_volume_backup_type),
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
// BootVolumeBackups can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:core/bootVolumeBackup:BootVolumeBackup test_boot_volume_backup "id"
// ```
type BootVolumeBackup struct {
	pulumi.CustomResourceState

	// The OCID of the boot volume that needs to be backed up. Cannot be defined if `sourceDetails` is defined.
	BootVolumeId pulumi.StringOutput `pulumi:"bootVolumeId"`
	// (Updatable) The OCID of the compartment that contains the boot volume backup.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the boot volume backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The date and time the volume backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for backups that were created automatically by a scheduled-backup policy. For manually created backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
	ExpirationTime pulumi.StringOutput `pulumi:"expirationTime"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The image OCID used to create the boot volume the backup is taken from.
	ImageId pulumi.StringOutput `pulumi:"imageId"`
	// The OCID of the KMS key in the destination region which will be the master encryption key for the copied volume backup.
	KmsKeyId pulumi.StringOutput `pulumi:"kmsKeyId"`
	// The size of the boot volume, in GBs.
	SizeInGbs pulumi.StringOutput `pulumi:"sizeInGbs"`
	// The OCID of the source boot volume backup.
	SourceBootVolumeBackupId pulumi.StringOutput `pulumi:"sourceBootVolumeBackupId"`
	// Details of the volume backup source in the cloud. Cannot be defined if `bootVolumeId` is defined.
	SourceDetails BootVolumeBackupSourceDetailsPtrOutput `pulumi:"sourceDetails"`
	// Specifies whether the backup was created manually, or via scheduled backup policy.
	SourceType pulumi.StringOutput `pulumi:"sourceType"`
	// The current state of a boot volume backup.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The date and time the boot volume backup was created. This is the time the actual point-in-time image of the volume data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the request to create the boot volume backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeRequestReceived pulumi.StringOutput `pulumi:"timeRequestReceived"`
	// The type of backup to create. If omitted, defaults to incremental. Supported values are 'FULL' or 'INCREMENTAL'.
	Type pulumi.StringOutput `pulumi:"type"`
	// The size used by the backup, in GBs. It is typically smaller than sizeInGBs, depending on the space consumed on the boot volume and whether the backup is full or incremental.
	UniqueSizeInGbs pulumi.StringOutput `pulumi:"uniqueSizeInGbs"`
}

// NewBootVolumeBackup registers a new resource with the given unique name, arguments, and options.
func NewBootVolumeBackup(ctx *pulumi.Context,
	name string, args *BootVolumeBackupArgs, opts ...pulumi.ResourceOption) (*BootVolumeBackup, error) {
	if args == nil {
		args = &BootVolumeBackupArgs{}
	}

	var resource BootVolumeBackup
	err := ctx.RegisterResource("oci:core/bootVolumeBackup:BootVolumeBackup", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetBootVolumeBackup gets an existing BootVolumeBackup resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetBootVolumeBackup(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *BootVolumeBackupState, opts ...pulumi.ResourceOption) (*BootVolumeBackup, error) {
	var resource BootVolumeBackup
	err := ctx.ReadResource("oci:core/bootVolumeBackup:BootVolumeBackup", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering BootVolumeBackup resources.
type bootVolumeBackupState struct {
	// The OCID of the boot volume that needs to be backed up. Cannot be defined if `sourceDetails` is defined.
	BootVolumeId *string `pulumi:"bootVolumeId"`
	// (Updatable) The OCID of the compartment that contains the boot volume backup.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the boot volume backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The date and time the volume backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for backups that were created automatically by a scheduled-backup policy. For manually created backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
	ExpirationTime *string `pulumi:"expirationTime"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The image OCID used to create the boot volume the backup is taken from.
	ImageId *string `pulumi:"imageId"`
	// The OCID of the KMS key in the destination region which will be the master encryption key for the copied volume backup.
	KmsKeyId *string `pulumi:"kmsKeyId"`
	// The size of the boot volume, in GBs.
	SizeInGbs *string `pulumi:"sizeInGbs"`
	// The OCID of the source boot volume backup.
	SourceBootVolumeBackupId *string `pulumi:"sourceBootVolumeBackupId"`
	// Details of the volume backup source in the cloud. Cannot be defined if `bootVolumeId` is defined.
	SourceDetails *BootVolumeBackupSourceDetails `pulumi:"sourceDetails"`
	// Specifies whether the backup was created manually, or via scheduled backup policy.
	SourceType *string `pulumi:"sourceType"`
	// The current state of a boot volume backup.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The date and time the boot volume backup was created. This is the time the actual point-in-time image of the volume data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the request to create the boot volume backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeRequestReceived *string `pulumi:"timeRequestReceived"`
	// The type of backup to create. If omitted, defaults to incremental. Supported values are 'FULL' or 'INCREMENTAL'.
	Type *string `pulumi:"type"`
	// The size used by the backup, in GBs. It is typically smaller than sizeInGBs, depending on the space consumed on the boot volume and whether the backup is full or incremental.
	UniqueSizeInGbs *string `pulumi:"uniqueSizeInGbs"`
}

type BootVolumeBackupState struct {
	// The OCID of the boot volume that needs to be backed up. Cannot be defined if `sourceDetails` is defined.
	BootVolumeId pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment that contains the boot volume backup.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name for the boot volume backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// The date and time the volume backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for backups that were created automatically by a scheduled-backup policy. For manually created backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
	ExpirationTime pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The image OCID used to create the boot volume the backup is taken from.
	ImageId pulumi.StringPtrInput
	// The OCID of the KMS key in the destination region which will be the master encryption key for the copied volume backup.
	KmsKeyId pulumi.StringPtrInput
	// The size of the boot volume, in GBs.
	SizeInGbs pulumi.StringPtrInput
	// The OCID of the source boot volume backup.
	SourceBootVolumeBackupId pulumi.StringPtrInput
	// Details of the volume backup source in the cloud. Cannot be defined if `bootVolumeId` is defined.
	SourceDetails BootVolumeBackupSourceDetailsPtrInput
	// Specifies whether the backup was created manually, or via scheduled backup policy.
	SourceType pulumi.StringPtrInput
	// The current state of a boot volume backup.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	SystemTags pulumi.MapInput
	// The date and time the boot volume backup was created. This is the time the actual point-in-time image of the volume data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The date and time the request to create the boot volume backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeRequestReceived pulumi.StringPtrInput
	// The type of backup to create. If omitted, defaults to incremental. Supported values are 'FULL' or 'INCREMENTAL'.
	Type pulumi.StringPtrInput
	// The size used by the backup, in GBs. It is typically smaller than sizeInGBs, depending on the space consumed on the boot volume and whether the backup is full or incremental.
	UniqueSizeInGbs pulumi.StringPtrInput
}

func (BootVolumeBackupState) ElementType() reflect.Type {
	return reflect.TypeOf((*bootVolumeBackupState)(nil)).Elem()
}

type bootVolumeBackupArgs struct {
	// The OCID of the boot volume that needs to be backed up. Cannot be defined if `sourceDetails` is defined.
	BootVolumeId *string `pulumi:"bootVolumeId"`
	// (Updatable) The OCID of the compartment that contains the boot volume backup.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the boot volume backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Details of the volume backup source in the cloud. Cannot be defined if `bootVolumeId` is defined.
	SourceDetails *BootVolumeBackupSourceDetails `pulumi:"sourceDetails"`
	// The type of backup to create. If omitted, defaults to incremental. Supported values are 'FULL' or 'INCREMENTAL'.
	Type *string `pulumi:"type"`
}

// The set of arguments for constructing a BootVolumeBackup resource.
type BootVolumeBackupArgs struct {
	// The OCID of the boot volume that needs to be backed up. Cannot be defined if `sourceDetails` is defined.
	BootVolumeId pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment that contains the boot volume backup.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name for the boot volume backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Details of the volume backup source in the cloud. Cannot be defined if `bootVolumeId` is defined.
	SourceDetails BootVolumeBackupSourceDetailsPtrInput
	// The type of backup to create. If omitted, defaults to incremental. Supported values are 'FULL' or 'INCREMENTAL'.
	Type pulumi.StringPtrInput
}

func (BootVolumeBackupArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*bootVolumeBackupArgs)(nil)).Elem()
}

type BootVolumeBackupInput interface {
	pulumi.Input

	ToBootVolumeBackupOutput() BootVolumeBackupOutput
	ToBootVolumeBackupOutputWithContext(ctx context.Context) BootVolumeBackupOutput
}

func (*BootVolumeBackup) ElementType() reflect.Type {
	return reflect.TypeOf((*BootVolumeBackup)(nil))
}

func (i *BootVolumeBackup) ToBootVolumeBackupOutput() BootVolumeBackupOutput {
	return i.ToBootVolumeBackupOutputWithContext(context.Background())
}

func (i *BootVolumeBackup) ToBootVolumeBackupOutputWithContext(ctx context.Context) BootVolumeBackupOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BootVolumeBackupOutput)
}

func (i *BootVolumeBackup) ToBootVolumeBackupPtrOutput() BootVolumeBackupPtrOutput {
	return i.ToBootVolumeBackupPtrOutputWithContext(context.Background())
}

func (i *BootVolumeBackup) ToBootVolumeBackupPtrOutputWithContext(ctx context.Context) BootVolumeBackupPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BootVolumeBackupPtrOutput)
}

type BootVolumeBackupPtrInput interface {
	pulumi.Input

	ToBootVolumeBackupPtrOutput() BootVolumeBackupPtrOutput
	ToBootVolumeBackupPtrOutputWithContext(ctx context.Context) BootVolumeBackupPtrOutput
}

type bootVolumeBackupPtrType BootVolumeBackupArgs

func (*bootVolumeBackupPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**BootVolumeBackup)(nil))
}

func (i *bootVolumeBackupPtrType) ToBootVolumeBackupPtrOutput() BootVolumeBackupPtrOutput {
	return i.ToBootVolumeBackupPtrOutputWithContext(context.Background())
}

func (i *bootVolumeBackupPtrType) ToBootVolumeBackupPtrOutputWithContext(ctx context.Context) BootVolumeBackupPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BootVolumeBackupPtrOutput)
}

// BootVolumeBackupArrayInput is an input type that accepts BootVolumeBackupArray and BootVolumeBackupArrayOutput values.
// You can construct a concrete instance of `BootVolumeBackupArrayInput` via:
//
//          BootVolumeBackupArray{ BootVolumeBackupArgs{...} }
type BootVolumeBackupArrayInput interface {
	pulumi.Input

	ToBootVolumeBackupArrayOutput() BootVolumeBackupArrayOutput
	ToBootVolumeBackupArrayOutputWithContext(context.Context) BootVolumeBackupArrayOutput
}

type BootVolumeBackupArray []BootVolumeBackupInput

func (BootVolumeBackupArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*BootVolumeBackup)(nil)).Elem()
}

func (i BootVolumeBackupArray) ToBootVolumeBackupArrayOutput() BootVolumeBackupArrayOutput {
	return i.ToBootVolumeBackupArrayOutputWithContext(context.Background())
}

func (i BootVolumeBackupArray) ToBootVolumeBackupArrayOutputWithContext(ctx context.Context) BootVolumeBackupArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BootVolumeBackupArrayOutput)
}

// BootVolumeBackupMapInput is an input type that accepts BootVolumeBackupMap and BootVolumeBackupMapOutput values.
// You can construct a concrete instance of `BootVolumeBackupMapInput` via:
//
//          BootVolumeBackupMap{ "key": BootVolumeBackupArgs{...} }
type BootVolumeBackupMapInput interface {
	pulumi.Input

	ToBootVolumeBackupMapOutput() BootVolumeBackupMapOutput
	ToBootVolumeBackupMapOutputWithContext(context.Context) BootVolumeBackupMapOutput
}

type BootVolumeBackupMap map[string]BootVolumeBackupInput

func (BootVolumeBackupMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*BootVolumeBackup)(nil)).Elem()
}

func (i BootVolumeBackupMap) ToBootVolumeBackupMapOutput() BootVolumeBackupMapOutput {
	return i.ToBootVolumeBackupMapOutputWithContext(context.Background())
}

func (i BootVolumeBackupMap) ToBootVolumeBackupMapOutputWithContext(ctx context.Context) BootVolumeBackupMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BootVolumeBackupMapOutput)
}

type BootVolumeBackupOutput struct {
	*pulumi.OutputState
}

func (BootVolumeBackupOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*BootVolumeBackup)(nil))
}

func (o BootVolumeBackupOutput) ToBootVolumeBackupOutput() BootVolumeBackupOutput {
	return o
}

func (o BootVolumeBackupOutput) ToBootVolumeBackupOutputWithContext(ctx context.Context) BootVolumeBackupOutput {
	return o
}

func (o BootVolumeBackupOutput) ToBootVolumeBackupPtrOutput() BootVolumeBackupPtrOutput {
	return o.ToBootVolumeBackupPtrOutputWithContext(context.Background())
}

func (o BootVolumeBackupOutput) ToBootVolumeBackupPtrOutputWithContext(ctx context.Context) BootVolumeBackupPtrOutput {
	return o.ApplyT(func(v BootVolumeBackup) *BootVolumeBackup {
		return &v
	}).(BootVolumeBackupPtrOutput)
}

type BootVolumeBackupPtrOutput struct {
	*pulumi.OutputState
}

func (BootVolumeBackupPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**BootVolumeBackup)(nil))
}

func (o BootVolumeBackupPtrOutput) ToBootVolumeBackupPtrOutput() BootVolumeBackupPtrOutput {
	return o
}

func (o BootVolumeBackupPtrOutput) ToBootVolumeBackupPtrOutputWithContext(ctx context.Context) BootVolumeBackupPtrOutput {
	return o
}

type BootVolumeBackupArrayOutput struct{ *pulumi.OutputState }

func (BootVolumeBackupArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]BootVolumeBackup)(nil))
}

func (o BootVolumeBackupArrayOutput) ToBootVolumeBackupArrayOutput() BootVolumeBackupArrayOutput {
	return o
}

func (o BootVolumeBackupArrayOutput) ToBootVolumeBackupArrayOutputWithContext(ctx context.Context) BootVolumeBackupArrayOutput {
	return o
}

func (o BootVolumeBackupArrayOutput) Index(i pulumi.IntInput) BootVolumeBackupOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) BootVolumeBackup {
		return vs[0].([]BootVolumeBackup)[vs[1].(int)]
	}).(BootVolumeBackupOutput)
}

type BootVolumeBackupMapOutput struct{ *pulumi.OutputState }

func (BootVolumeBackupMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]BootVolumeBackup)(nil))
}

func (o BootVolumeBackupMapOutput) ToBootVolumeBackupMapOutput() BootVolumeBackupMapOutput {
	return o
}

func (o BootVolumeBackupMapOutput) ToBootVolumeBackupMapOutputWithContext(ctx context.Context) BootVolumeBackupMapOutput {
	return o
}

func (o BootVolumeBackupMapOutput) MapIndex(k pulumi.StringInput) BootVolumeBackupOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) BootVolumeBackup {
		return vs[0].(map[string]BootVolumeBackup)[vs[1].(string)]
	}).(BootVolumeBackupOutput)
}

func init() {
	pulumi.RegisterOutputType(BootVolumeBackupOutput{})
	pulumi.RegisterOutputType(BootVolumeBackupPtrOutput{})
	pulumi.RegisterOutputType(BootVolumeBackupArrayOutput{})
	pulumi.RegisterOutputType(BootVolumeBackupMapOutput{})
}
