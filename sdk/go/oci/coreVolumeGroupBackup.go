// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Volume Group Backup resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new backup volume group of the specified volume group.
// For more information, see [Volume Groups](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/volumegroups.htm).
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
// 		_, err := oci.NewCoreVolumeGroupBackup(ctx, "testVolumeGroupBackup", &oci.CoreVolumeGroupBackupArgs{
// 			VolumeGroupId: pulumi.Any(oci_core_volume_group.Test_volume_group.Id),
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			DisplayName: pulumi.Any(_var.Volume_group_backup_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
// 			Type: pulumi.Any(_var.Volume_group_backup_type),
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
// VolumeGroupBackups can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/coreVolumeGroupBackup:CoreVolumeGroupBackup test_volume_group_backup "id"
// ```
type CoreVolumeGroupBackup struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment that will contain the volume group backup. This parameter is optional, by default backup will be created in the same compartment and source volume group.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the volume group backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The date and time the volume group backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for volume group backups that were created automatically by a scheduled-backup policy. For manually created volume group backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
	ExpirationTime pulumi.StringOutput `pulumi:"expirationTime"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The aggregate size of the volume group backup, in GBs.
	SizeInGbs pulumi.StringOutput `pulumi:"sizeInGbs"`
	// The aggregate size of the volume group backup, in MBs.
	SizeInMbs pulumi.StringOutput `pulumi:"sizeInMbs"`
	// Details of the volume group backup source in the cloud.
	SourceDetails CoreVolumeGroupBackupSourceDetailsPtrOutput `pulumi:"sourceDetails"`
	// Specifies whether the volume group backup was created manually, or via scheduled backup policy.
	SourceType pulumi.StringOutput `pulumi:"sourceType"`
	// The OCID of the source volume group backup.
	SourceVolumeGroupBackupId pulumi.StringOutput `pulumi:"sourceVolumeGroupBackupId"`
	// The current state of a volume group backup.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the volume group backup was created. This is the time the actual point-in-time image of the volume group data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the request to create the volume group backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeRequestReceived pulumi.StringOutput `pulumi:"timeRequestReceived"`
	// The type of backup to create. If omitted, defaults to incremental.
	// * Allowed values are :
	// * FULL
	// * INCREMENTAL
	Type pulumi.StringOutput `pulumi:"type"`
	// The aggregate size used by the volume group backup, in GBs.  It is typically smaller than `sizeInGbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
	UniqueSizeInGbs pulumi.StringOutput `pulumi:"uniqueSizeInGbs"`
	// The aggregate size used by the volume group backup, in MBs.  It is typically smaller than `sizeInMbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
	UniqueSizeInMbs pulumi.StringOutput `pulumi:"uniqueSizeInMbs"`
	// OCIDs for the volume backups in this volume group backup.
	VolumeBackupIds pulumi.StringArrayOutput `pulumi:"volumeBackupIds"`
	// The OCID of the volume group that needs to be backed up.
	VolumeGroupId pulumi.StringOutput `pulumi:"volumeGroupId"`
}

// NewCoreVolumeGroupBackup registers a new resource with the given unique name, arguments, and options.
func NewCoreVolumeGroupBackup(ctx *pulumi.Context,
	name string, args *CoreVolumeGroupBackupArgs, opts ...pulumi.ResourceOption) (*CoreVolumeGroupBackup, error) {
	if args == nil {
		args = &CoreVolumeGroupBackupArgs{}
	}

	var resource CoreVolumeGroupBackup
	err := ctx.RegisterResource("oci:index/coreVolumeGroupBackup:CoreVolumeGroupBackup", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCoreVolumeGroupBackup gets an existing CoreVolumeGroupBackup resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCoreVolumeGroupBackup(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CoreVolumeGroupBackupState, opts ...pulumi.ResourceOption) (*CoreVolumeGroupBackup, error) {
	var resource CoreVolumeGroupBackup
	err := ctx.ReadResource("oci:index/coreVolumeGroupBackup:CoreVolumeGroupBackup", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CoreVolumeGroupBackup resources.
type coreVolumeGroupBackupState struct {
	// (Updatable) The OCID of the compartment that will contain the volume group backup. This parameter is optional, by default backup will be created in the same compartment and source volume group.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the volume group backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The date and time the volume group backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for volume group backups that were created automatically by a scheduled-backup policy. For manually created volume group backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
	ExpirationTime *string `pulumi:"expirationTime"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The aggregate size of the volume group backup, in GBs.
	SizeInGbs *string `pulumi:"sizeInGbs"`
	// The aggregate size of the volume group backup, in MBs.
	SizeInMbs *string `pulumi:"sizeInMbs"`
	// Details of the volume group backup source in the cloud.
	SourceDetails *CoreVolumeGroupBackupSourceDetails `pulumi:"sourceDetails"`
	// Specifies whether the volume group backup was created manually, or via scheduled backup policy.
	SourceType *string `pulumi:"sourceType"`
	// The OCID of the source volume group backup.
	SourceVolumeGroupBackupId *string `pulumi:"sourceVolumeGroupBackupId"`
	// The current state of a volume group backup.
	State *string `pulumi:"state"`
	// The date and time the volume group backup was created. This is the time the actual point-in-time image of the volume group data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the request to create the volume group backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeRequestReceived *string `pulumi:"timeRequestReceived"`
	// The type of backup to create. If omitted, defaults to incremental.
	// * Allowed values are :
	// * FULL
	// * INCREMENTAL
	Type *string `pulumi:"type"`
	// The aggregate size used by the volume group backup, in GBs.  It is typically smaller than `sizeInGbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
	UniqueSizeInGbs *string `pulumi:"uniqueSizeInGbs"`
	// The aggregate size used by the volume group backup, in MBs.  It is typically smaller than `sizeInMbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
	UniqueSizeInMbs *string `pulumi:"uniqueSizeInMbs"`
	// OCIDs for the volume backups in this volume group backup.
	VolumeBackupIds []string `pulumi:"volumeBackupIds"`
	// The OCID of the volume group that needs to be backed up.
	VolumeGroupId *string `pulumi:"volumeGroupId"`
}

type CoreVolumeGroupBackupState struct {
	// (Updatable) The OCID of the compartment that will contain the volume group backup. This parameter is optional, by default backup will be created in the same compartment and source volume group.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name for the volume group backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// The date and time the volume group backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for volume group backups that were created automatically by a scheduled-backup policy. For manually created volume group backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
	ExpirationTime pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The aggregate size of the volume group backup, in GBs.
	SizeInGbs pulumi.StringPtrInput
	// The aggregate size of the volume group backup, in MBs.
	SizeInMbs pulumi.StringPtrInput
	// Details of the volume group backup source in the cloud.
	SourceDetails CoreVolumeGroupBackupSourceDetailsPtrInput
	// Specifies whether the volume group backup was created manually, or via scheduled backup policy.
	SourceType pulumi.StringPtrInput
	// The OCID of the source volume group backup.
	SourceVolumeGroupBackupId pulumi.StringPtrInput
	// The current state of a volume group backup.
	State pulumi.StringPtrInput
	// The date and time the volume group backup was created. This is the time the actual point-in-time image of the volume group data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The date and time the request to create the volume group backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeRequestReceived pulumi.StringPtrInput
	// The type of backup to create. If omitted, defaults to incremental.
	// * Allowed values are :
	// * FULL
	// * INCREMENTAL
	Type pulumi.StringPtrInput
	// The aggregate size used by the volume group backup, in GBs.  It is typically smaller than `sizeInGbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
	UniqueSizeInGbs pulumi.StringPtrInput
	// The aggregate size used by the volume group backup, in MBs.  It is typically smaller than `sizeInMbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
	UniqueSizeInMbs pulumi.StringPtrInput
	// OCIDs for the volume backups in this volume group backup.
	VolumeBackupIds pulumi.StringArrayInput
	// The OCID of the volume group that needs to be backed up.
	VolumeGroupId pulumi.StringPtrInput
}

func (CoreVolumeGroupBackupState) ElementType() reflect.Type {
	return reflect.TypeOf((*coreVolumeGroupBackupState)(nil)).Elem()
}

type coreVolumeGroupBackupArgs struct {
	// (Updatable) The OCID of the compartment that will contain the volume group backup. This parameter is optional, by default backup will be created in the same compartment and source volume group.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the volume group backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Details of the volume group backup source in the cloud.
	SourceDetails *CoreVolumeGroupBackupSourceDetails `pulumi:"sourceDetails"`
	// The type of backup to create. If omitted, defaults to incremental.
	// * Allowed values are :
	// * FULL
	// * INCREMENTAL
	Type *string `pulumi:"type"`
	// The OCID of the volume group that needs to be backed up.
	VolumeGroupId *string `pulumi:"volumeGroupId"`
}

// The set of arguments for constructing a CoreVolumeGroupBackup resource.
type CoreVolumeGroupBackupArgs struct {
	// (Updatable) The OCID of the compartment that will contain the volume group backup. This parameter is optional, by default backup will be created in the same compartment and source volume group.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name for the volume group backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Details of the volume group backup source in the cloud.
	SourceDetails CoreVolumeGroupBackupSourceDetailsPtrInput
	// The type of backup to create. If omitted, defaults to incremental.
	// * Allowed values are :
	// * FULL
	// * INCREMENTAL
	Type pulumi.StringPtrInput
	// The OCID of the volume group that needs to be backed up.
	VolumeGroupId pulumi.StringPtrInput
}

func (CoreVolumeGroupBackupArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*coreVolumeGroupBackupArgs)(nil)).Elem()
}

type CoreVolumeGroupBackupInput interface {
	pulumi.Input

	ToCoreVolumeGroupBackupOutput() CoreVolumeGroupBackupOutput
	ToCoreVolumeGroupBackupOutputWithContext(ctx context.Context) CoreVolumeGroupBackupOutput
}

func (*CoreVolumeGroupBackup) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreVolumeGroupBackup)(nil))
}

func (i *CoreVolumeGroupBackup) ToCoreVolumeGroupBackupOutput() CoreVolumeGroupBackupOutput {
	return i.ToCoreVolumeGroupBackupOutputWithContext(context.Background())
}

func (i *CoreVolumeGroupBackup) ToCoreVolumeGroupBackupOutputWithContext(ctx context.Context) CoreVolumeGroupBackupOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreVolumeGroupBackupOutput)
}

func (i *CoreVolumeGroupBackup) ToCoreVolumeGroupBackupPtrOutput() CoreVolumeGroupBackupPtrOutput {
	return i.ToCoreVolumeGroupBackupPtrOutputWithContext(context.Background())
}

func (i *CoreVolumeGroupBackup) ToCoreVolumeGroupBackupPtrOutputWithContext(ctx context.Context) CoreVolumeGroupBackupPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreVolumeGroupBackupPtrOutput)
}

type CoreVolumeGroupBackupPtrInput interface {
	pulumi.Input

	ToCoreVolumeGroupBackupPtrOutput() CoreVolumeGroupBackupPtrOutput
	ToCoreVolumeGroupBackupPtrOutputWithContext(ctx context.Context) CoreVolumeGroupBackupPtrOutput
}

type coreVolumeGroupBackupPtrType CoreVolumeGroupBackupArgs

func (*coreVolumeGroupBackupPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreVolumeGroupBackup)(nil))
}

func (i *coreVolumeGroupBackupPtrType) ToCoreVolumeGroupBackupPtrOutput() CoreVolumeGroupBackupPtrOutput {
	return i.ToCoreVolumeGroupBackupPtrOutputWithContext(context.Background())
}

func (i *coreVolumeGroupBackupPtrType) ToCoreVolumeGroupBackupPtrOutputWithContext(ctx context.Context) CoreVolumeGroupBackupPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreVolumeGroupBackupPtrOutput)
}

// CoreVolumeGroupBackupArrayInput is an input type that accepts CoreVolumeGroupBackupArray and CoreVolumeGroupBackupArrayOutput values.
// You can construct a concrete instance of `CoreVolumeGroupBackupArrayInput` via:
//
//          CoreVolumeGroupBackupArray{ CoreVolumeGroupBackupArgs{...} }
type CoreVolumeGroupBackupArrayInput interface {
	pulumi.Input

	ToCoreVolumeGroupBackupArrayOutput() CoreVolumeGroupBackupArrayOutput
	ToCoreVolumeGroupBackupArrayOutputWithContext(context.Context) CoreVolumeGroupBackupArrayOutput
}

type CoreVolumeGroupBackupArray []CoreVolumeGroupBackupInput

func (CoreVolumeGroupBackupArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CoreVolumeGroupBackup)(nil)).Elem()
}

func (i CoreVolumeGroupBackupArray) ToCoreVolumeGroupBackupArrayOutput() CoreVolumeGroupBackupArrayOutput {
	return i.ToCoreVolumeGroupBackupArrayOutputWithContext(context.Background())
}

func (i CoreVolumeGroupBackupArray) ToCoreVolumeGroupBackupArrayOutputWithContext(ctx context.Context) CoreVolumeGroupBackupArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreVolumeGroupBackupArrayOutput)
}

// CoreVolumeGroupBackupMapInput is an input type that accepts CoreVolumeGroupBackupMap and CoreVolumeGroupBackupMapOutput values.
// You can construct a concrete instance of `CoreVolumeGroupBackupMapInput` via:
//
//          CoreVolumeGroupBackupMap{ "key": CoreVolumeGroupBackupArgs{...} }
type CoreVolumeGroupBackupMapInput interface {
	pulumi.Input

	ToCoreVolumeGroupBackupMapOutput() CoreVolumeGroupBackupMapOutput
	ToCoreVolumeGroupBackupMapOutputWithContext(context.Context) CoreVolumeGroupBackupMapOutput
}

type CoreVolumeGroupBackupMap map[string]CoreVolumeGroupBackupInput

func (CoreVolumeGroupBackupMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CoreVolumeGroupBackup)(nil)).Elem()
}

func (i CoreVolumeGroupBackupMap) ToCoreVolumeGroupBackupMapOutput() CoreVolumeGroupBackupMapOutput {
	return i.ToCoreVolumeGroupBackupMapOutputWithContext(context.Background())
}

func (i CoreVolumeGroupBackupMap) ToCoreVolumeGroupBackupMapOutputWithContext(ctx context.Context) CoreVolumeGroupBackupMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreVolumeGroupBackupMapOutput)
}

type CoreVolumeGroupBackupOutput struct {
	*pulumi.OutputState
}

func (CoreVolumeGroupBackupOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreVolumeGroupBackup)(nil))
}

func (o CoreVolumeGroupBackupOutput) ToCoreVolumeGroupBackupOutput() CoreVolumeGroupBackupOutput {
	return o
}

func (o CoreVolumeGroupBackupOutput) ToCoreVolumeGroupBackupOutputWithContext(ctx context.Context) CoreVolumeGroupBackupOutput {
	return o
}

func (o CoreVolumeGroupBackupOutput) ToCoreVolumeGroupBackupPtrOutput() CoreVolumeGroupBackupPtrOutput {
	return o.ToCoreVolumeGroupBackupPtrOutputWithContext(context.Background())
}

func (o CoreVolumeGroupBackupOutput) ToCoreVolumeGroupBackupPtrOutputWithContext(ctx context.Context) CoreVolumeGroupBackupPtrOutput {
	return o.ApplyT(func(v CoreVolumeGroupBackup) *CoreVolumeGroupBackup {
		return &v
	}).(CoreVolumeGroupBackupPtrOutput)
}

type CoreVolumeGroupBackupPtrOutput struct {
	*pulumi.OutputState
}

func (CoreVolumeGroupBackupPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreVolumeGroupBackup)(nil))
}

func (o CoreVolumeGroupBackupPtrOutput) ToCoreVolumeGroupBackupPtrOutput() CoreVolumeGroupBackupPtrOutput {
	return o
}

func (o CoreVolumeGroupBackupPtrOutput) ToCoreVolumeGroupBackupPtrOutputWithContext(ctx context.Context) CoreVolumeGroupBackupPtrOutput {
	return o
}

type CoreVolumeGroupBackupArrayOutput struct{ *pulumi.OutputState }

func (CoreVolumeGroupBackupArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CoreVolumeGroupBackup)(nil))
}

func (o CoreVolumeGroupBackupArrayOutput) ToCoreVolumeGroupBackupArrayOutput() CoreVolumeGroupBackupArrayOutput {
	return o
}

func (o CoreVolumeGroupBackupArrayOutput) ToCoreVolumeGroupBackupArrayOutputWithContext(ctx context.Context) CoreVolumeGroupBackupArrayOutput {
	return o
}

func (o CoreVolumeGroupBackupArrayOutput) Index(i pulumi.IntInput) CoreVolumeGroupBackupOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CoreVolumeGroupBackup {
		return vs[0].([]CoreVolumeGroupBackup)[vs[1].(int)]
	}).(CoreVolumeGroupBackupOutput)
}

type CoreVolumeGroupBackupMapOutput struct{ *pulumi.OutputState }

func (CoreVolumeGroupBackupMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CoreVolumeGroupBackup)(nil))
}

func (o CoreVolumeGroupBackupMapOutput) ToCoreVolumeGroupBackupMapOutput() CoreVolumeGroupBackupMapOutput {
	return o
}

func (o CoreVolumeGroupBackupMapOutput) ToCoreVolumeGroupBackupMapOutputWithContext(ctx context.Context) CoreVolumeGroupBackupMapOutput {
	return o
}

func (o CoreVolumeGroupBackupMapOutput) MapIndex(k pulumi.StringInput) CoreVolumeGroupBackupOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CoreVolumeGroupBackup {
		return vs[0].(map[string]CoreVolumeGroupBackup)[vs[1].(string)]
	}).(CoreVolumeGroupBackupOutput)
}

func init() {
	pulumi.RegisterOutputType(CoreVolumeGroupBackupOutput{})
	pulumi.RegisterOutputType(CoreVolumeGroupBackupPtrOutput{})
	pulumi.RegisterOutputType(CoreVolumeGroupBackupArrayOutput{})
	pulumi.RegisterOutputType(CoreVolumeGroupBackupMapOutput{})
}
