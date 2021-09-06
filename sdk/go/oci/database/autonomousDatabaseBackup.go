// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Autonomous Database Backup resource in Oracle Cloud Infrastructure Database service.
//
// Creates a new Autonomous Database backup for the specified database based on the provided request parameters.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/database"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := database.NewAutonomousDatabaseBackup(ctx, "testAutonomousDatabaseBackup", &database.AutonomousDatabaseBackupArgs{
// 			AutonomousDatabaseId: pulumi.Any(oci_database_autonomous_database.Test_autonomous_database.Id),
// 			DisplayName:          pulumi.Any(_var.Autonomous_database_backup_display_name),
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
// AutonomousDatabaseBackups can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:database/autonomousDatabaseBackup:AutonomousDatabaseBackup test_autonomous_database_backup "id"
// ```
type AutonomousDatabaseBackup struct {
	pulumi.CustomResourceState

	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
	AutonomousDatabaseId pulumi.StringOutput `pulumi:"autonomousDatabaseId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The size of the database in terabytes at the time the backup was taken.
	DatabaseSizeInTbs pulumi.Float64Output `pulumi:"databaseSizeInTbs"`
	// The user-friendly name for the backup. The name does not have to be unique.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// Indicates whether the backup is user-initiated or automatic.
	IsAutomatic pulumi.BoolOutput `pulumi:"isAutomatic"`
	// Indicates whether the backup can be used to restore the associated Autonomous Database.
	IsRestorable pulumi.BoolOutput `pulumi:"isRestorable"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
	KeyStoreId pulumi.StringOutput `pulumi:"keyStoreId"`
	// The wallet name for Oracle Key Vault.
	KeyStoreWalletName pulumi.StringOutput `pulumi:"keyStoreWalletName"`
	// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
	KmsKeyId pulumi.StringOutput `pulumi:"kmsKeyId"`
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The current state of the backup.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the backup completed.
	TimeEnded pulumi.StringOutput `pulumi:"timeEnded"`
	// The date and time the backup started.
	TimeStarted pulumi.StringOutput `pulumi:"timeStarted"`
	// The type of backup.
	Type pulumi.StringOutput `pulumi:"type"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
	VaultId pulumi.StringOutput `pulumi:"vaultId"`
}

// NewAutonomousDatabaseBackup registers a new resource with the given unique name, arguments, and options.
func NewAutonomousDatabaseBackup(ctx *pulumi.Context,
	name string, args *AutonomousDatabaseBackupArgs, opts ...pulumi.ResourceOption) (*AutonomousDatabaseBackup, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AutonomousDatabaseId == nil {
		return nil, errors.New("invalid value for required argument 'AutonomousDatabaseId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	var resource AutonomousDatabaseBackup
	err := ctx.RegisterResource("oci:database/autonomousDatabaseBackup:AutonomousDatabaseBackup", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAutonomousDatabaseBackup gets an existing AutonomousDatabaseBackup resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAutonomousDatabaseBackup(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AutonomousDatabaseBackupState, opts ...pulumi.ResourceOption) (*AutonomousDatabaseBackup, error) {
	var resource AutonomousDatabaseBackup
	err := ctx.ReadResource("oci:database/autonomousDatabaseBackup:AutonomousDatabaseBackup", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering AutonomousDatabaseBackup resources.
type autonomousDatabaseBackupState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
	AutonomousDatabaseId *string `pulumi:"autonomousDatabaseId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The size of the database in terabytes at the time the backup was taken.
	DatabaseSizeInTbs *float64 `pulumi:"databaseSizeInTbs"`
	// The user-friendly name for the backup. The name does not have to be unique.
	DisplayName *string `pulumi:"displayName"`
	// Indicates whether the backup is user-initiated or automatic.
	IsAutomatic *bool `pulumi:"isAutomatic"`
	// Indicates whether the backup can be used to restore the associated Autonomous Database.
	IsRestorable *bool `pulumi:"isRestorable"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
	KeyStoreId *string `pulumi:"keyStoreId"`
	// The wallet name for Oracle Key Vault.
	KeyStoreWalletName *string `pulumi:"keyStoreWalletName"`
	// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
	KmsKeyId *string `pulumi:"kmsKeyId"`
	// Additional information about the current lifecycle state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The current state of the backup.
	State *string `pulumi:"state"`
	// The date and time the backup completed.
	TimeEnded *string `pulumi:"timeEnded"`
	// The date and time the backup started.
	TimeStarted *string `pulumi:"timeStarted"`
	// The type of backup.
	Type *string `pulumi:"type"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
	VaultId *string `pulumi:"vaultId"`
}

type AutonomousDatabaseBackupState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
	AutonomousDatabaseId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// The size of the database in terabytes at the time the backup was taken.
	DatabaseSizeInTbs pulumi.Float64PtrInput
	// The user-friendly name for the backup. The name does not have to be unique.
	DisplayName pulumi.StringPtrInput
	// Indicates whether the backup is user-initiated or automatic.
	IsAutomatic pulumi.BoolPtrInput
	// Indicates whether the backup can be used to restore the associated Autonomous Database.
	IsRestorable pulumi.BoolPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
	KeyStoreId pulumi.StringPtrInput
	// The wallet name for Oracle Key Vault.
	KeyStoreWalletName pulumi.StringPtrInput
	// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
	KmsKeyId pulumi.StringPtrInput
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringPtrInput
	// The current state of the backup.
	State pulumi.StringPtrInput
	// The date and time the backup completed.
	TimeEnded pulumi.StringPtrInput
	// The date and time the backup started.
	TimeStarted pulumi.StringPtrInput
	// The type of backup.
	Type pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
	VaultId pulumi.StringPtrInput
}

func (AutonomousDatabaseBackupState) ElementType() reflect.Type {
	return reflect.TypeOf((*autonomousDatabaseBackupState)(nil)).Elem()
}

type autonomousDatabaseBackupArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
	AutonomousDatabaseId string `pulumi:"autonomousDatabaseId"`
	// The user-friendly name for the backup. The name does not have to be unique.
	DisplayName string `pulumi:"displayName"`
}

// The set of arguments for constructing a AutonomousDatabaseBackup resource.
type AutonomousDatabaseBackupArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
	AutonomousDatabaseId pulumi.StringInput
	// The user-friendly name for the backup. The name does not have to be unique.
	DisplayName pulumi.StringInput
}

func (AutonomousDatabaseBackupArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*autonomousDatabaseBackupArgs)(nil)).Elem()
}

type AutonomousDatabaseBackupInput interface {
	pulumi.Input

	ToAutonomousDatabaseBackupOutput() AutonomousDatabaseBackupOutput
	ToAutonomousDatabaseBackupOutputWithContext(ctx context.Context) AutonomousDatabaseBackupOutput
}

func (*AutonomousDatabaseBackup) ElementType() reflect.Type {
	return reflect.TypeOf((*AutonomousDatabaseBackup)(nil))
}

func (i *AutonomousDatabaseBackup) ToAutonomousDatabaseBackupOutput() AutonomousDatabaseBackupOutput {
	return i.ToAutonomousDatabaseBackupOutputWithContext(context.Background())
}

func (i *AutonomousDatabaseBackup) ToAutonomousDatabaseBackupOutputWithContext(ctx context.Context) AutonomousDatabaseBackupOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutonomousDatabaseBackupOutput)
}

func (i *AutonomousDatabaseBackup) ToAutonomousDatabaseBackupPtrOutput() AutonomousDatabaseBackupPtrOutput {
	return i.ToAutonomousDatabaseBackupPtrOutputWithContext(context.Background())
}

func (i *AutonomousDatabaseBackup) ToAutonomousDatabaseBackupPtrOutputWithContext(ctx context.Context) AutonomousDatabaseBackupPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutonomousDatabaseBackupPtrOutput)
}

type AutonomousDatabaseBackupPtrInput interface {
	pulumi.Input

	ToAutonomousDatabaseBackupPtrOutput() AutonomousDatabaseBackupPtrOutput
	ToAutonomousDatabaseBackupPtrOutputWithContext(ctx context.Context) AutonomousDatabaseBackupPtrOutput
}

type autonomousDatabaseBackupPtrType AutonomousDatabaseBackupArgs

func (*autonomousDatabaseBackupPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**AutonomousDatabaseBackup)(nil))
}

func (i *autonomousDatabaseBackupPtrType) ToAutonomousDatabaseBackupPtrOutput() AutonomousDatabaseBackupPtrOutput {
	return i.ToAutonomousDatabaseBackupPtrOutputWithContext(context.Background())
}

func (i *autonomousDatabaseBackupPtrType) ToAutonomousDatabaseBackupPtrOutputWithContext(ctx context.Context) AutonomousDatabaseBackupPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutonomousDatabaseBackupPtrOutput)
}

// AutonomousDatabaseBackupArrayInput is an input type that accepts AutonomousDatabaseBackupArray and AutonomousDatabaseBackupArrayOutput values.
// You can construct a concrete instance of `AutonomousDatabaseBackupArrayInput` via:
//
//          AutonomousDatabaseBackupArray{ AutonomousDatabaseBackupArgs{...} }
type AutonomousDatabaseBackupArrayInput interface {
	pulumi.Input

	ToAutonomousDatabaseBackupArrayOutput() AutonomousDatabaseBackupArrayOutput
	ToAutonomousDatabaseBackupArrayOutputWithContext(context.Context) AutonomousDatabaseBackupArrayOutput
}

type AutonomousDatabaseBackupArray []AutonomousDatabaseBackupInput

func (AutonomousDatabaseBackupArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AutonomousDatabaseBackup)(nil)).Elem()
}

func (i AutonomousDatabaseBackupArray) ToAutonomousDatabaseBackupArrayOutput() AutonomousDatabaseBackupArrayOutput {
	return i.ToAutonomousDatabaseBackupArrayOutputWithContext(context.Background())
}

func (i AutonomousDatabaseBackupArray) ToAutonomousDatabaseBackupArrayOutputWithContext(ctx context.Context) AutonomousDatabaseBackupArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutonomousDatabaseBackupArrayOutput)
}

// AutonomousDatabaseBackupMapInput is an input type that accepts AutonomousDatabaseBackupMap and AutonomousDatabaseBackupMapOutput values.
// You can construct a concrete instance of `AutonomousDatabaseBackupMapInput` via:
//
//          AutonomousDatabaseBackupMap{ "key": AutonomousDatabaseBackupArgs{...} }
type AutonomousDatabaseBackupMapInput interface {
	pulumi.Input

	ToAutonomousDatabaseBackupMapOutput() AutonomousDatabaseBackupMapOutput
	ToAutonomousDatabaseBackupMapOutputWithContext(context.Context) AutonomousDatabaseBackupMapOutput
}

type AutonomousDatabaseBackupMap map[string]AutonomousDatabaseBackupInput

func (AutonomousDatabaseBackupMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AutonomousDatabaseBackup)(nil)).Elem()
}

func (i AutonomousDatabaseBackupMap) ToAutonomousDatabaseBackupMapOutput() AutonomousDatabaseBackupMapOutput {
	return i.ToAutonomousDatabaseBackupMapOutputWithContext(context.Background())
}

func (i AutonomousDatabaseBackupMap) ToAutonomousDatabaseBackupMapOutputWithContext(ctx context.Context) AutonomousDatabaseBackupMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutonomousDatabaseBackupMapOutput)
}

type AutonomousDatabaseBackupOutput struct {
	*pulumi.OutputState
}

func (AutonomousDatabaseBackupOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*AutonomousDatabaseBackup)(nil))
}

func (o AutonomousDatabaseBackupOutput) ToAutonomousDatabaseBackupOutput() AutonomousDatabaseBackupOutput {
	return o
}

func (o AutonomousDatabaseBackupOutput) ToAutonomousDatabaseBackupOutputWithContext(ctx context.Context) AutonomousDatabaseBackupOutput {
	return o
}

func (o AutonomousDatabaseBackupOutput) ToAutonomousDatabaseBackupPtrOutput() AutonomousDatabaseBackupPtrOutput {
	return o.ToAutonomousDatabaseBackupPtrOutputWithContext(context.Background())
}

func (o AutonomousDatabaseBackupOutput) ToAutonomousDatabaseBackupPtrOutputWithContext(ctx context.Context) AutonomousDatabaseBackupPtrOutput {
	return o.ApplyT(func(v AutonomousDatabaseBackup) *AutonomousDatabaseBackup {
		return &v
	}).(AutonomousDatabaseBackupPtrOutput)
}

type AutonomousDatabaseBackupPtrOutput struct {
	*pulumi.OutputState
}

func (AutonomousDatabaseBackupPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**AutonomousDatabaseBackup)(nil))
}

func (o AutonomousDatabaseBackupPtrOutput) ToAutonomousDatabaseBackupPtrOutput() AutonomousDatabaseBackupPtrOutput {
	return o
}

func (o AutonomousDatabaseBackupPtrOutput) ToAutonomousDatabaseBackupPtrOutputWithContext(ctx context.Context) AutonomousDatabaseBackupPtrOutput {
	return o
}

type AutonomousDatabaseBackupArrayOutput struct{ *pulumi.OutputState }

func (AutonomousDatabaseBackupArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]AutonomousDatabaseBackup)(nil))
}

func (o AutonomousDatabaseBackupArrayOutput) ToAutonomousDatabaseBackupArrayOutput() AutonomousDatabaseBackupArrayOutput {
	return o
}

func (o AutonomousDatabaseBackupArrayOutput) ToAutonomousDatabaseBackupArrayOutputWithContext(ctx context.Context) AutonomousDatabaseBackupArrayOutput {
	return o
}

func (o AutonomousDatabaseBackupArrayOutput) Index(i pulumi.IntInput) AutonomousDatabaseBackupOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) AutonomousDatabaseBackup {
		return vs[0].([]AutonomousDatabaseBackup)[vs[1].(int)]
	}).(AutonomousDatabaseBackupOutput)
}

type AutonomousDatabaseBackupMapOutput struct{ *pulumi.OutputState }

func (AutonomousDatabaseBackupMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]AutonomousDatabaseBackup)(nil))
}

func (o AutonomousDatabaseBackupMapOutput) ToAutonomousDatabaseBackupMapOutput() AutonomousDatabaseBackupMapOutput {
	return o
}

func (o AutonomousDatabaseBackupMapOutput) ToAutonomousDatabaseBackupMapOutputWithContext(ctx context.Context) AutonomousDatabaseBackupMapOutput {
	return o
}

func (o AutonomousDatabaseBackupMapOutput) MapIndex(k pulumi.StringInput) AutonomousDatabaseBackupOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) AutonomousDatabaseBackup {
		return vs[0].(map[string]AutonomousDatabaseBackup)[vs[1].(string)]
	}).(AutonomousDatabaseBackupOutput)
}

func init() {
	pulumi.RegisterOutputType(AutonomousDatabaseBackupOutput{})
	pulumi.RegisterOutputType(AutonomousDatabaseBackupPtrOutput{})
	pulumi.RegisterOutputType(AutonomousDatabaseBackupArrayOutput{})
	pulumi.RegisterOutputType(AutonomousDatabaseBackupMapOutput{})
}
