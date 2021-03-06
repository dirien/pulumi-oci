// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Volume Backup resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new backup of the specified volume. For general information about volume backups,
// see [Overview of Block Volume Service Backups](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumebackups.htm)
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
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := oci.NewCoreVolumeBackup(ctx, "testVolumeBackup", &oci.CoreVolumeBackupArgs{
// 			VolumeId: pulumi.Any(oci_core_volume.Test_volume.Id),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			DisplayName: pulumi.Any(_var.Volume_backup_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
// 			Type: pulumi.Any(_var.Volume_backup_type),
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
// VolumeBackups can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/coreVolumeBackup:CoreVolumeBackup test_volume_backup "id"
// ```
type CoreVolumeBackup struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment that contains the volume backup.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the volume backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The date and time the volume backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for backups that were created automatically by a scheduled-backup policy. For manually created backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
	ExpirationTime pulumi.StringOutput `pulumi:"expirationTime"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The OCID of the KMS key in the destination region which will be the master encryption key for the copied volume backup.
	KmsKeyId pulumi.StringOutput `pulumi:"kmsKeyId"`
	// The size of the volume, in GBs.
	SizeInGbs pulumi.StringOutput `pulumi:"sizeInGbs"`
	// The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Please use `sizeInGbs`.
	//
	// Deprecated: The 'size_in_mbs' field has been deprecated. Please use 'size_in_gbs' instead.
	SizeInMbs pulumi.StringOutput `pulumi:"sizeInMbs"`
	// Details of the volume backup source in the cloud.
	SourceDetails CoreVolumeBackupSourceDetailsPtrOutput `pulumi:"sourceDetails"`
	// Specifies whether the backup was created manually, or via scheduled backup policy.
	SourceType pulumi.StringOutput `pulumi:"sourceType"`
	// The OCID of the source volume backup.
	SourceVolumeBackupId pulumi.StringOutput `pulumi:"sourceVolumeBackupId"`
	// The current state of a volume backup.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The date and time the volume backup was created. This is the time the actual point-in-time image of the volume data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the request to create the volume backup was received. Format defined by [RFC3339]https://tools.ietf.org/html/rfc3339.
	TimeRequestReceived pulumi.StringOutput `pulumi:"timeRequestReceived"`
	// The type of backup to create. If omitted, defaults to INCREMENTAL. Supported values are 'FULL' or 'INCREMENTAL'.
	Type pulumi.StringOutput `pulumi:"type"`
	// The size used by the backup, in GBs. It is typically smaller than sizeInGBs, depending on the space consumed on the volume and whether the backup is full or incremental.
	UniqueSizeInGbs pulumi.StringOutput `pulumi:"uniqueSizeInGbs"`
	// The size used by the backup, in MBs. It is typically smaller than sizeInMBs, depending on the space consumed on the volume and whether the backup is full or incremental. This field is deprecated. Please use uniqueSizeInGBs.
	//
	// Deprecated: The 'unique_size_in_mbs' field has been deprecated. Please use 'unique_size_in_gbs' instead.
	UniqueSizeInMbs pulumi.StringOutput `pulumi:"uniqueSizeInMbs"`
	// The OCID of the volume that needs to be backed up.**Note: To create the resource either `volumeId` or `sourceDetails` is required to be set.
	VolumeId pulumi.StringOutput `pulumi:"volumeId"`
}

// NewCoreVolumeBackup registers a new resource with the given unique name, arguments, and options.
func NewCoreVolumeBackup(ctx *pulumi.Context,
	name string, args *CoreVolumeBackupArgs, opts ...pulumi.ResourceOption) (*CoreVolumeBackup, error) {
	if args == nil {
		args = &CoreVolumeBackupArgs{}
	}

	var resource CoreVolumeBackup
	err := ctx.RegisterResource("oci:index/coreVolumeBackup:CoreVolumeBackup", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCoreVolumeBackup gets an existing CoreVolumeBackup resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCoreVolumeBackup(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CoreVolumeBackupState, opts ...pulumi.ResourceOption) (*CoreVolumeBackup, error) {
	var resource CoreVolumeBackup
	err := ctx.ReadResource("oci:index/coreVolumeBackup:CoreVolumeBackup", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CoreVolumeBackup resources.
type coreVolumeBackupState struct {
	// (Updatable) The OCID of the compartment that contains the volume backup.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the volume backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The date and time the volume backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for backups that were created automatically by a scheduled-backup policy. For manually created backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
	ExpirationTime *string `pulumi:"expirationTime"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the KMS key in the destination region which will be the master encryption key for the copied volume backup.
	KmsKeyId *string `pulumi:"kmsKeyId"`
	// The size of the volume, in GBs.
	SizeInGbs *string `pulumi:"sizeInGbs"`
	// The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Please use `sizeInGbs`.
	//
	// Deprecated: The 'size_in_mbs' field has been deprecated. Please use 'size_in_gbs' instead.
	SizeInMbs *string `pulumi:"sizeInMbs"`
	// Details of the volume backup source in the cloud.
	SourceDetails *CoreVolumeBackupSourceDetails `pulumi:"sourceDetails"`
	// Specifies whether the backup was created manually, or via scheduled backup policy.
	SourceType *string `pulumi:"sourceType"`
	// The OCID of the source volume backup.
	SourceVolumeBackupId *string `pulumi:"sourceVolumeBackupId"`
	// The current state of a volume backup.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The date and time the volume backup was created. This is the time the actual point-in-time image of the volume data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the request to create the volume backup was received. Format defined by [RFC3339]https://tools.ietf.org/html/rfc3339.
	TimeRequestReceived *string `pulumi:"timeRequestReceived"`
	// The type of backup to create. If omitted, defaults to INCREMENTAL. Supported values are 'FULL' or 'INCREMENTAL'.
	Type *string `pulumi:"type"`
	// The size used by the backup, in GBs. It is typically smaller than sizeInGBs, depending on the space consumed on the volume and whether the backup is full or incremental.
	UniqueSizeInGbs *string `pulumi:"uniqueSizeInGbs"`
	// The size used by the backup, in MBs. It is typically smaller than sizeInMBs, depending on the space consumed on the volume and whether the backup is full or incremental. This field is deprecated. Please use uniqueSizeInGBs.
	//
	// Deprecated: The 'unique_size_in_mbs' field has been deprecated. Please use 'unique_size_in_gbs' instead.
	UniqueSizeInMbs *string `pulumi:"uniqueSizeInMbs"`
	// The OCID of the volume that needs to be backed up.**Note: To create the resource either `volumeId` or `sourceDetails` is required to be set.
	VolumeId *string `pulumi:"volumeId"`
}

type CoreVolumeBackupState struct {
	// (Updatable) The OCID of the compartment that contains the volume backup.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name for the volume backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// The date and time the volume backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for backups that were created automatically by a scheduled-backup policy. For manually created backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
	ExpirationTime pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The OCID of the KMS key in the destination region which will be the master encryption key for the copied volume backup.
	KmsKeyId pulumi.StringPtrInput
	// The size of the volume, in GBs.
	SizeInGbs pulumi.StringPtrInput
	// The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Please use `sizeInGbs`.
	//
	// Deprecated: The 'size_in_mbs' field has been deprecated. Please use 'size_in_gbs' instead.
	SizeInMbs pulumi.StringPtrInput
	// Details of the volume backup source in the cloud.
	SourceDetails CoreVolumeBackupSourceDetailsPtrInput
	// Specifies whether the backup was created manually, or via scheduled backup policy.
	SourceType pulumi.StringPtrInput
	// The OCID of the source volume backup.
	SourceVolumeBackupId pulumi.StringPtrInput
	// The current state of a volume backup.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	SystemTags pulumi.MapInput
	// The date and time the volume backup was created. This is the time the actual point-in-time image of the volume data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The date and time the request to create the volume backup was received. Format defined by [RFC3339]https://tools.ietf.org/html/rfc3339.
	TimeRequestReceived pulumi.StringPtrInput
	// The type of backup to create. If omitted, defaults to INCREMENTAL. Supported values are 'FULL' or 'INCREMENTAL'.
	Type pulumi.StringPtrInput
	// The size used by the backup, in GBs. It is typically smaller than sizeInGBs, depending on the space consumed on the volume and whether the backup is full or incremental.
	UniqueSizeInGbs pulumi.StringPtrInput
	// The size used by the backup, in MBs. It is typically smaller than sizeInMBs, depending on the space consumed on the volume and whether the backup is full or incremental. This field is deprecated. Please use uniqueSizeInGBs.
	//
	// Deprecated: The 'unique_size_in_mbs' field has been deprecated. Please use 'unique_size_in_gbs' instead.
	UniqueSizeInMbs pulumi.StringPtrInput
	// The OCID of the volume that needs to be backed up.**Note: To create the resource either `volumeId` or `sourceDetails` is required to be set.
	VolumeId pulumi.StringPtrInput
}

func (CoreVolumeBackupState) ElementType() reflect.Type {
	return reflect.TypeOf((*coreVolumeBackupState)(nil)).Elem()
}

type coreVolumeBackupArgs struct {
	// (Updatable) The OCID of the compartment that contains the volume backup.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the volume backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Details of the volume backup source in the cloud.
	SourceDetails *CoreVolumeBackupSourceDetails `pulumi:"sourceDetails"`
	// The type of backup to create. If omitted, defaults to INCREMENTAL. Supported values are 'FULL' or 'INCREMENTAL'.
	Type *string `pulumi:"type"`
	// The OCID of the volume that needs to be backed up.**Note: To create the resource either `volumeId` or `sourceDetails` is required to be set.
	VolumeId *string `pulumi:"volumeId"`
}

// The set of arguments for constructing a CoreVolumeBackup resource.
type CoreVolumeBackupArgs struct {
	// (Updatable) The OCID of the compartment that contains the volume backup.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name for the volume backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Details of the volume backup source in the cloud.
	SourceDetails CoreVolumeBackupSourceDetailsPtrInput
	// The type of backup to create. If omitted, defaults to INCREMENTAL. Supported values are 'FULL' or 'INCREMENTAL'.
	Type pulumi.StringPtrInput
	// The OCID of the volume that needs to be backed up.**Note: To create the resource either `volumeId` or `sourceDetails` is required to be set.
	VolumeId pulumi.StringPtrInput
}

func (CoreVolumeBackupArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*coreVolumeBackupArgs)(nil)).Elem()
}

type CoreVolumeBackupInput interface {
	pulumi.Input

	ToCoreVolumeBackupOutput() CoreVolumeBackupOutput
	ToCoreVolumeBackupOutputWithContext(ctx context.Context) CoreVolumeBackupOutput
}

func (*CoreVolumeBackup) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreVolumeBackup)(nil))
}

func (i *CoreVolumeBackup) ToCoreVolumeBackupOutput() CoreVolumeBackupOutput {
	return i.ToCoreVolumeBackupOutputWithContext(context.Background())
}

func (i *CoreVolumeBackup) ToCoreVolumeBackupOutputWithContext(ctx context.Context) CoreVolumeBackupOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreVolumeBackupOutput)
}

func (i *CoreVolumeBackup) ToCoreVolumeBackupPtrOutput() CoreVolumeBackupPtrOutput {
	return i.ToCoreVolumeBackupPtrOutputWithContext(context.Background())
}

func (i *CoreVolumeBackup) ToCoreVolumeBackupPtrOutputWithContext(ctx context.Context) CoreVolumeBackupPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreVolumeBackupPtrOutput)
}

type CoreVolumeBackupPtrInput interface {
	pulumi.Input

	ToCoreVolumeBackupPtrOutput() CoreVolumeBackupPtrOutput
	ToCoreVolumeBackupPtrOutputWithContext(ctx context.Context) CoreVolumeBackupPtrOutput
}

type coreVolumeBackupPtrType CoreVolumeBackupArgs

func (*coreVolumeBackupPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreVolumeBackup)(nil))
}

func (i *coreVolumeBackupPtrType) ToCoreVolumeBackupPtrOutput() CoreVolumeBackupPtrOutput {
	return i.ToCoreVolumeBackupPtrOutputWithContext(context.Background())
}

func (i *coreVolumeBackupPtrType) ToCoreVolumeBackupPtrOutputWithContext(ctx context.Context) CoreVolumeBackupPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreVolumeBackupPtrOutput)
}

// CoreVolumeBackupArrayInput is an input type that accepts CoreVolumeBackupArray and CoreVolumeBackupArrayOutput values.
// You can construct a concrete instance of `CoreVolumeBackupArrayInput` via:
//
//          CoreVolumeBackupArray{ CoreVolumeBackupArgs{...} }
type CoreVolumeBackupArrayInput interface {
	pulumi.Input

	ToCoreVolumeBackupArrayOutput() CoreVolumeBackupArrayOutput
	ToCoreVolumeBackupArrayOutputWithContext(context.Context) CoreVolumeBackupArrayOutput
}

type CoreVolumeBackupArray []CoreVolumeBackupInput

func (CoreVolumeBackupArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CoreVolumeBackup)(nil)).Elem()
}

func (i CoreVolumeBackupArray) ToCoreVolumeBackupArrayOutput() CoreVolumeBackupArrayOutput {
	return i.ToCoreVolumeBackupArrayOutputWithContext(context.Background())
}

func (i CoreVolumeBackupArray) ToCoreVolumeBackupArrayOutputWithContext(ctx context.Context) CoreVolumeBackupArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreVolumeBackupArrayOutput)
}

// CoreVolumeBackupMapInput is an input type that accepts CoreVolumeBackupMap and CoreVolumeBackupMapOutput values.
// You can construct a concrete instance of `CoreVolumeBackupMapInput` via:
//
//          CoreVolumeBackupMap{ "key": CoreVolumeBackupArgs{...} }
type CoreVolumeBackupMapInput interface {
	pulumi.Input

	ToCoreVolumeBackupMapOutput() CoreVolumeBackupMapOutput
	ToCoreVolumeBackupMapOutputWithContext(context.Context) CoreVolumeBackupMapOutput
}

type CoreVolumeBackupMap map[string]CoreVolumeBackupInput

func (CoreVolumeBackupMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CoreVolumeBackup)(nil)).Elem()
}

func (i CoreVolumeBackupMap) ToCoreVolumeBackupMapOutput() CoreVolumeBackupMapOutput {
	return i.ToCoreVolumeBackupMapOutputWithContext(context.Background())
}

func (i CoreVolumeBackupMap) ToCoreVolumeBackupMapOutputWithContext(ctx context.Context) CoreVolumeBackupMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreVolumeBackupMapOutput)
}

type CoreVolumeBackupOutput struct {
	*pulumi.OutputState
}

func (CoreVolumeBackupOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreVolumeBackup)(nil))
}

func (o CoreVolumeBackupOutput) ToCoreVolumeBackupOutput() CoreVolumeBackupOutput {
	return o
}

func (o CoreVolumeBackupOutput) ToCoreVolumeBackupOutputWithContext(ctx context.Context) CoreVolumeBackupOutput {
	return o
}

func (o CoreVolumeBackupOutput) ToCoreVolumeBackupPtrOutput() CoreVolumeBackupPtrOutput {
	return o.ToCoreVolumeBackupPtrOutputWithContext(context.Background())
}

func (o CoreVolumeBackupOutput) ToCoreVolumeBackupPtrOutputWithContext(ctx context.Context) CoreVolumeBackupPtrOutput {
	return o.ApplyT(func(v CoreVolumeBackup) *CoreVolumeBackup {
		return &v
	}).(CoreVolumeBackupPtrOutput)
}

type CoreVolumeBackupPtrOutput struct {
	*pulumi.OutputState
}

func (CoreVolumeBackupPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreVolumeBackup)(nil))
}

func (o CoreVolumeBackupPtrOutput) ToCoreVolumeBackupPtrOutput() CoreVolumeBackupPtrOutput {
	return o
}

func (o CoreVolumeBackupPtrOutput) ToCoreVolumeBackupPtrOutputWithContext(ctx context.Context) CoreVolumeBackupPtrOutput {
	return o
}

type CoreVolumeBackupArrayOutput struct{ *pulumi.OutputState }

func (CoreVolumeBackupArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CoreVolumeBackup)(nil))
}

func (o CoreVolumeBackupArrayOutput) ToCoreVolumeBackupArrayOutput() CoreVolumeBackupArrayOutput {
	return o
}

func (o CoreVolumeBackupArrayOutput) ToCoreVolumeBackupArrayOutputWithContext(ctx context.Context) CoreVolumeBackupArrayOutput {
	return o
}

func (o CoreVolumeBackupArrayOutput) Index(i pulumi.IntInput) CoreVolumeBackupOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CoreVolumeBackup {
		return vs[0].([]CoreVolumeBackup)[vs[1].(int)]
	}).(CoreVolumeBackupOutput)
}

type CoreVolumeBackupMapOutput struct{ *pulumi.OutputState }

func (CoreVolumeBackupMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CoreVolumeBackup)(nil))
}

func (o CoreVolumeBackupMapOutput) ToCoreVolumeBackupMapOutput() CoreVolumeBackupMapOutput {
	return o
}

func (o CoreVolumeBackupMapOutput) ToCoreVolumeBackupMapOutputWithContext(ctx context.Context) CoreVolumeBackupMapOutput {
	return o
}

func (o CoreVolumeBackupMapOutput) MapIndex(k pulumi.StringInput) CoreVolumeBackupOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CoreVolumeBackup {
		return vs[0].(map[string]CoreVolumeBackup)[vs[1].(string)]
	}).(CoreVolumeBackupOutput)
}

func init() {
	pulumi.RegisterOutputType(CoreVolumeBackupOutput{})
	pulumi.RegisterOutputType(CoreVolumeBackupPtrOutput{})
	pulumi.RegisterOutputType(CoreVolumeBackupArrayOutput{})
	pulumi.RegisterOutputType(CoreVolumeBackupMapOutput{})
}
