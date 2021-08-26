// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Migration resource in Oracle Cloud Infrastructure Database service.
//
// Migrates the Exadata DB system to the new [Exadata resource model](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/exaflexsystem.htm#exaflexsystem_topic-resource_model).
// All related resources will be migrated.
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
// 		_, err := database.NewMigration(ctx, "testMigration", &database.MigrationArgs{
// 			DbSystemId: pulumi.Any(oci_database_db_system.Test_db_system.Id),
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
// Import is not supported for this resource.
type Migration struct {
	pulumi.CustomResourceState

	// The details of addtional resources related to the migration.
	AdditionalMigrations MigrationAdditionalMigrationArrayOutput `pulumi:"additionalMigrations"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure.
	CloudExadataInfrastructureId pulumi.StringOutput `pulumi:"cloudExadataInfrastructureId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud VM cluster.
	CloudVmClusterId pulumi.StringOutput `pulumi:"cloudVmClusterId"`
	// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId pulumi.StringOutput `pulumi:"dbSystemId"`
}

// NewMigration registers a new resource with the given unique name, arguments, and options.
func NewMigration(ctx *pulumi.Context,
	name string, args *MigrationArgs, opts ...pulumi.ResourceOption) (*Migration, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.DbSystemId == nil {
		return nil, errors.New("invalid value for required argument 'DbSystemId'")
	}
	var resource Migration
	err := ctx.RegisterResource("oci:database/migration:Migration", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetMigration gets an existing Migration resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetMigration(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *MigrationState, opts ...pulumi.ResourceOption) (*Migration, error) {
	var resource Migration
	err := ctx.ReadResource("oci:database/migration:Migration", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Migration resources.
type migrationState struct {
	// The details of addtional resources related to the migration.
	AdditionalMigrations []MigrationAdditionalMigration `pulumi:"additionalMigrations"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure.
	CloudExadataInfrastructureId *string `pulumi:"cloudExadataInfrastructureId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud VM cluster.
	CloudVmClusterId *string `pulumi:"cloudVmClusterId"`
	// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId *string `pulumi:"dbSystemId"`
}

type MigrationState struct {
	// The details of addtional resources related to the migration.
	AdditionalMigrations MigrationAdditionalMigrationArrayInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure.
	CloudExadataInfrastructureId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud VM cluster.
	CloudVmClusterId pulumi.StringPtrInput
	// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId pulumi.StringPtrInput
}

func (MigrationState) ElementType() reflect.Type {
	return reflect.TypeOf((*migrationState)(nil)).Elem()
}

type migrationArgs struct {
	// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId string `pulumi:"dbSystemId"`
}

// The set of arguments for constructing a Migration resource.
type MigrationArgs struct {
	// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId pulumi.StringInput
}

func (MigrationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*migrationArgs)(nil)).Elem()
}

type MigrationInput interface {
	pulumi.Input

	ToMigrationOutput() MigrationOutput
	ToMigrationOutputWithContext(ctx context.Context) MigrationOutput
}

func (*Migration) ElementType() reflect.Type {
	return reflect.TypeOf((*Migration)(nil))
}

func (i *Migration) ToMigrationOutput() MigrationOutput {
	return i.ToMigrationOutputWithContext(context.Background())
}

func (i *Migration) ToMigrationOutputWithContext(ctx context.Context) MigrationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MigrationOutput)
}

func (i *Migration) ToMigrationPtrOutput() MigrationPtrOutput {
	return i.ToMigrationPtrOutputWithContext(context.Background())
}

func (i *Migration) ToMigrationPtrOutputWithContext(ctx context.Context) MigrationPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MigrationPtrOutput)
}

type MigrationPtrInput interface {
	pulumi.Input

	ToMigrationPtrOutput() MigrationPtrOutput
	ToMigrationPtrOutputWithContext(ctx context.Context) MigrationPtrOutput
}

type migrationPtrType MigrationArgs

func (*migrationPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**Migration)(nil))
}

func (i *migrationPtrType) ToMigrationPtrOutput() MigrationPtrOutput {
	return i.ToMigrationPtrOutputWithContext(context.Background())
}

func (i *migrationPtrType) ToMigrationPtrOutputWithContext(ctx context.Context) MigrationPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MigrationPtrOutput)
}

// MigrationArrayInput is an input type that accepts MigrationArray and MigrationArrayOutput values.
// You can construct a concrete instance of `MigrationArrayInput` via:
//
//          MigrationArray{ MigrationArgs{...} }
type MigrationArrayInput interface {
	pulumi.Input

	ToMigrationArrayOutput() MigrationArrayOutput
	ToMigrationArrayOutputWithContext(context.Context) MigrationArrayOutput
}

type MigrationArray []MigrationInput

func (MigrationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Migration)(nil)).Elem()
}

func (i MigrationArray) ToMigrationArrayOutput() MigrationArrayOutput {
	return i.ToMigrationArrayOutputWithContext(context.Background())
}

func (i MigrationArray) ToMigrationArrayOutputWithContext(ctx context.Context) MigrationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MigrationArrayOutput)
}

// MigrationMapInput is an input type that accepts MigrationMap and MigrationMapOutput values.
// You can construct a concrete instance of `MigrationMapInput` via:
//
//          MigrationMap{ "key": MigrationArgs{...} }
type MigrationMapInput interface {
	pulumi.Input

	ToMigrationMapOutput() MigrationMapOutput
	ToMigrationMapOutputWithContext(context.Context) MigrationMapOutput
}

type MigrationMap map[string]MigrationInput

func (MigrationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Migration)(nil)).Elem()
}

func (i MigrationMap) ToMigrationMapOutput() MigrationMapOutput {
	return i.ToMigrationMapOutputWithContext(context.Background())
}

func (i MigrationMap) ToMigrationMapOutputWithContext(ctx context.Context) MigrationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MigrationMapOutput)
}

type MigrationOutput struct {
	*pulumi.OutputState
}

func (MigrationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*Migration)(nil))
}

func (o MigrationOutput) ToMigrationOutput() MigrationOutput {
	return o
}

func (o MigrationOutput) ToMigrationOutputWithContext(ctx context.Context) MigrationOutput {
	return o
}

func (o MigrationOutput) ToMigrationPtrOutput() MigrationPtrOutput {
	return o.ToMigrationPtrOutputWithContext(context.Background())
}

func (o MigrationOutput) ToMigrationPtrOutputWithContext(ctx context.Context) MigrationPtrOutput {
	return o.ApplyT(func(v Migration) *Migration {
		return &v
	}).(MigrationPtrOutput)
}

type MigrationPtrOutput struct {
	*pulumi.OutputState
}

func (MigrationPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Migration)(nil))
}

func (o MigrationPtrOutput) ToMigrationPtrOutput() MigrationPtrOutput {
	return o
}

func (o MigrationPtrOutput) ToMigrationPtrOutputWithContext(ctx context.Context) MigrationPtrOutput {
	return o
}

type MigrationArrayOutput struct{ *pulumi.OutputState }

func (MigrationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]Migration)(nil))
}

func (o MigrationArrayOutput) ToMigrationArrayOutput() MigrationArrayOutput {
	return o
}

func (o MigrationArrayOutput) ToMigrationArrayOutputWithContext(ctx context.Context) MigrationArrayOutput {
	return o
}

func (o MigrationArrayOutput) Index(i pulumi.IntInput) MigrationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) Migration {
		return vs[0].([]Migration)[vs[1].(int)]
	}).(MigrationOutput)
}

type MigrationMapOutput struct{ *pulumi.OutputState }

func (MigrationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]Migration)(nil))
}

func (o MigrationMapOutput) ToMigrationMapOutput() MigrationMapOutput {
	return o
}

func (o MigrationMapOutput) ToMigrationMapOutputWithContext(ctx context.Context) MigrationMapOutput {
	return o
}

func (o MigrationMapOutput) MapIndex(k pulumi.StringInput) MigrationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) Migration {
		return vs[0].(map[string]Migration)[vs[1].(string)]
	}).(MigrationOutput)
}

func init() {
	pulumi.RegisterOutputType(MigrationOutput{})
	pulumi.RegisterOutputType(MigrationPtrOutput{})
	pulumi.RegisterOutputType(MigrationArrayOutput{})
	pulumi.RegisterOutputType(MigrationMapOutput{})
}