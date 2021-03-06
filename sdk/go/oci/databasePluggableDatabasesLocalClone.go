// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Pluggable Databases Local Clone resource in Oracle Cloud Infrastructure Database service. Although pluggable databases(PDB) belong to a container database(CDB), there is no change to the parent(CDB) as a result of this operation.
//
// Clones and starts a pluggable database (PDB) in the same database (CDB) as the source PDB. The source PDB must be in the `READ_WRITE` openMode to perform the clone operation.
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
// 		_, err := oci.NewDatabasePluggableDatabasesLocalClone(ctx, "testPluggableDatabasesLocalClone", &oci.DatabasePluggableDatabasesLocalCloneArgs{
// 			ClonedPdbName:           pulumi.Any(_var.Pluggable_databases_local_clone_cloned_pdb_name),
// 			PdbAdminPassword:        pulumi.Any(_var.Pluggable_databases_local_clone_pdb_admin_password),
// 			PluggableDatabaseId:     pulumi.Any(oci_database_pluggable_database.Test_pluggable_database.Id),
// 			TargetTdeWalletPassword: pulumi.Any(_var.Pluggable_databases_local_clone_target_tde_wallet_password),
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
type DatabasePluggableDatabasesLocalClone struct {
	pulumi.CustomResourceState

	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	ClonedPdbName pulumi.StringOutput `pulumi:"clonedPdbName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Connection strings to connect to an Oracle Pluggable Database.
	ConnectionStrings DatabasePluggableDatabasesLocalCloneConnectionStringsOutput `pulumi:"connectionStrings"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB.
	ContainerDatabaseId pulumi.StringOutput `pulumi:"containerDatabaseId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The restricted mode of the pluggable database. If a pluggable database is opened in restricted mode, the user needs both create a session and have restricted session privileges to connect to it.
	IsRestricted pulumi.BoolOutput `pulumi:"isRestricted"`
	// Detailed message for the lifecycle state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
	OpenMode pulumi.StringOutput `pulumi:"openMode"`
	// A strong password for PDB Admin of the newly cloned PDB. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
	PdbAdminPassword pulumi.StringOutput `pulumi:"pdbAdminPassword"`
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	PdbName pulumi.StringOutput `pulumi:"pdbName"`
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	PluggableDatabaseId pulumi.StringOutput `pulumi:"pluggableDatabaseId"`
	// The current state of the pluggable database.
	State pulumi.StringOutput `pulumi:"state"`
	// The existing TDE wallet password of the target CDB.
	TargetTdeWalletPassword pulumi.StringOutput `pulumi:"targetTdeWalletPassword"`
	// The date and time the pluggable database was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewDatabasePluggableDatabasesLocalClone registers a new resource with the given unique name, arguments, and options.
func NewDatabasePluggableDatabasesLocalClone(ctx *pulumi.Context,
	name string, args *DatabasePluggableDatabasesLocalCloneArgs, opts ...pulumi.ResourceOption) (*DatabasePluggableDatabasesLocalClone, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ClonedPdbName == nil {
		return nil, errors.New("invalid value for required argument 'ClonedPdbName'")
	}
	if args.PdbAdminPassword == nil {
		return nil, errors.New("invalid value for required argument 'PdbAdminPassword'")
	}
	if args.PluggableDatabaseId == nil {
		return nil, errors.New("invalid value for required argument 'PluggableDatabaseId'")
	}
	if args.TargetTdeWalletPassword == nil {
		return nil, errors.New("invalid value for required argument 'TargetTdeWalletPassword'")
	}
	var resource DatabasePluggableDatabasesLocalClone
	err := ctx.RegisterResource("oci:index/databasePluggableDatabasesLocalClone:DatabasePluggableDatabasesLocalClone", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDatabasePluggableDatabasesLocalClone gets an existing DatabasePluggableDatabasesLocalClone resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDatabasePluggableDatabasesLocalClone(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DatabasePluggableDatabasesLocalCloneState, opts ...pulumi.ResourceOption) (*DatabasePluggableDatabasesLocalClone, error) {
	var resource DatabasePluggableDatabasesLocalClone
	err := ctx.ReadResource("oci:index/databasePluggableDatabasesLocalClone:DatabasePluggableDatabasesLocalClone", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DatabasePluggableDatabasesLocalClone resources.
type databasePluggableDatabasesLocalCloneState struct {
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	ClonedPdbName *string `pulumi:"clonedPdbName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// Connection strings to connect to an Oracle Pluggable Database.
	ConnectionStrings *DatabasePluggableDatabasesLocalCloneConnectionStrings `pulumi:"connectionStrings"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB.
	ContainerDatabaseId *string `pulumi:"containerDatabaseId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The restricted mode of the pluggable database. If a pluggable database is opened in restricted mode, the user needs both create a session and have restricted session privileges to connect to it.
	IsRestricted *bool `pulumi:"isRestricted"`
	// Detailed message for the lifecycle state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
	OpenMode *string `pulumi:"openMode"`
	// A strong password for PDB Admin of the newly cloned PDB. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
	PdbAdminPassword *string `pulumi:"pdbAdminPassword"`
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	PdbName *string `pulumi:"pdbName"`
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	PluggableDatabaseId *string `pulumi:"pluggableDatabaseId"`
	// The current state of the pluggable database.
	State *string `pulumi:"state"`
	// The existing TDE wallet password of the target CDB.
	TargetTdeWalletPassword *string `pulumi:"targetTdeWalletPassword"`
	// The date and time the pluggable database was created.
	TimeCreated *string `pulumi:"timeCreated"`
}

type DatabasePluggableDatabasesLocalCloneState struct {
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	ClonedPdbName pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// Connection strings to connect to an Oracle Pluggable Database.
	ConnectionStrings DatabasePluggableDatabasesLocalCloneConnectionStringsPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB.
	ContainerDatabaseId pulumi.StringPtrInput
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.MapInput
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The restricted mode of the pluggable database. If a pluggable database is opened in restricted mode, the user needs both create a session and have restricted session privileges to connect to it.
	IsRestricted pulumi.BoolPtrInput
	// Detailed message for the lifecycle state.
	LifecycleDetails pulumi.StringPtrInput
	// The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
	OpenMode pulumi.StringPtrInput
	// A strong password for PDB Admin of the newly cloned PDB. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
	PdbAdminPassword pulumi.StringPtrInput
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	PdbName pulumi.StringPtrInput
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	PluggableDatabaseId pulumi.StringPtrInput
	// The current state of the pluggable database.
	State pulumi.StringPtrInput
	// The existing TDE wallet password of the target CDB.
	TargetTdeWalletPassword pulumi.StringPtrInput
	// The date and time the pluggable database was created.
	TimeCreated pulumi.StringPtrInput
}

func (DatabasePluggableDatabasesLocalCloneState) ElementType() reflect.Type {
	return reflect.TypeOf((*databasePluggableDatabasesLocalCloneState)(nil)).Elem()
}

type databasePluggableDatabasesLocalCloneArgs struct {
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	ClonedPdbName string `pulumi:"clonedPdbName"`
	// A strong password for PDB Admin of the newly cloned PDB. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
	PdbAdminPassword string `pulumi:"pdbAdminPassword"`
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	PluggableDatabaseId string `pulumi:"pluggableDatabaseId"`
	// The existing TDE wallet password of the target CDB.
	TargetTdeWalletPassword string `pulumi:"targetTdeWalletPassword"`
}

// The set of arguments for constructing a DatabasePluggableDatabasesLocalClone resource.
type DatabasePluggableDatabasesLocalCloneArgs struct {
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	ClonedPdbName pulumi.StringInput
	// A strong password for PDB Admin of the newly cloned PDB. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
	PdbAdminPassword pulumi.StringInput
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	PluggableDatabaseId pulumi.StringInput
	// The existing TDE wallet password of the target CDB.
	TargetTdeWalletPassword pulumi.StringInput
}

func (DatabasePluggableDatabasesLocalCloneArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*databasePluggableDatabasesLocalCloneArgs)(nil)).Elem()
}

type DatabasePluggableDatabasesLocalCloneInput interface {
	pulumi.Input

	ToDatabasePluggableDatabasesLocalCloneOutput() DatabasePluggableDatabasesLocalCloneOutput
	ToDatabasePluggableDatabasesLocalCloneOutputWithContext(ctx context.Context) DatabasePluggableDatabasesLocalCloneOutput
}

func (*DatabasePluggableDatabasesLocalClone) ElementType() reflect.Type {
	return reflect.TypeOf((*DatabasePluggableDatabasesLocalClone)(nil))
}

func (i *DatabasePluggableDatabasesLocalClone) ToDatabasePluggableDatabasesLocalCloneOutput() DatabasePluggableDatabasesLocalCloneOutput {
	return i.ToDatabasePluggableDatabasesLocalCloneOutputWithContext(context.Background())
}

func (i *DatabasePluggableDatabasesLocalClone) ToDatabasePluggableDatabasesLocalCloneOutputWithContext(ctx context.Context) DatabasePluggableDatabasesLocalCloneOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabasePluggableDatabasesLocalCloneOutput)
}

func (i *DatabasePluggableDatabasesLocalClone) ToDatabasePluggableDatabasesLocalClonePtrOutput() DatabasePluggableDatabasesLocalClonePtrOutput {
	return i.ToDatabasePluggableDatabasesLocalClonePtrOutputWithContext(context.Background())
}

func (i *DatabasePluggableDatabasesLocalClone) ToDatabasePluggableDatabasesLocalClonePtrOutputWithContext(ctx context.Context) DatabasePluggableDatabasesLocalClonePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabasePluggableDatabasesLocalClonePtrOutput)
}

type DatabasePluggableDatabasesLocalClonePtrInput interface {
	pulumi.Input

	ToDatabasePluggableDatabasesLocalClonePtrOutput() DatabasePluggableDatabasesLocalClonePtrOutput
	ToDatabasePluggableDatabasesLocalClonePtrOutputWithContext(ctx context.Context) DatabasePluggableDatabasesLocalClonePtrOutput
}

type databasePluggableDatabasesLocalClonePtrType DatabasePluggableDatabasesLocalCloneArgs

func (*databasePluggableDatabasesLocalClonePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**DatabasePluggableDatabasesLocalClone)(nil))
}

func (i *databasePluggableDatabasesLocalClonePtrType) ToDatabasePluggableDatabasesLocalClonePtrOutput() DatabasePluggableDatabasesLocalClonePtrOutput {
	return i.ToDatabasePluggableDatabasesLocalClonePtrOutputWithContext(context.Background())
}

func (i *databasePluggableDatabasesLocalClonePtrType) ToDatabasePluggableDatabasesLocalClonePtrOutputWithContext(ctx context.Context) DatabasePluggableDatabasesLocalClonePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabasePluggableDatabasesLocalClonePtrOutput)
}

// DatabasePluggableDatabasesLocalCloneArrayInput is an input type that accepts DatabasePluggableDatabasesLocalCloneArray and DatabasePluggableDatabasesLocalCloneArrayOutput values.
// You can construct a concrete instance of `DatabasePluggableDatabasesLocalCloneArrayInput` via:
//
//          DatabasePluggableDatabasesLocalCloneArray{ DatabasePluggableDatabasesLocalCloneArgs{...} }
type DatabasePluggableDatabasesLocalCloneArrayInput interface {
	pulumi.Input

	ToDatabasePluggableDatabasesLocalCloneArrayOutput() DatabasePluggableDatabasesLocalCloneArrayOutput
	ToDatabasePluggableDatabasesLocalCloneArrayOutputWithContext(context.Context) DatabasePluggableDatabasesLocalCloneArrayOutput
}

type DatabasePluggableDatabasesLocalCloneArray []DatabasePluggableDatabasesLocalCloneInput

func (DatabasePluggableDatabasesLocalCloneArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DatabasePluggableDatabasesLocalClone)(nil)).Elem()
}

func (i DatabasePluggableDatabasesLocalCloneArray) ToDatabasePluggableDatabasesLocalCloneArrayOutput() DatabasePluggableDatabasesLocalCloneArrayOutput {
	return i.ToDatabasePluggableDatabasesLocalCloneArrayOutputWithContext(context.Background())
}

func (i DatabasePluggableDatabasesLocalCloneArray) ToDatabasePluggableDatabasesLocalCloneArrayOutputWithContext(ctx context.Context) DatabasePluggableDatabasesLocalCloneArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabasePluggableDatabasesLocalCloneArrayOutput)
}

// DatabasePluggableDatabasesLocalCloneMapInput is an input type that accepts DatabasePluggableDatabasesLocalCloneMap and DatabasePluggableDatabasesLocalCloneMapOutput values.
// You can construct a concrete instance of `DatabasePluggableDatabasesLocalCloneMapInput` via:
//
//          DatabasePluggableDatabasesLocalCloneMap{ "key": DatabasePluggableDatabasesLocalCloneArgs{...} }
type DatabasePluggableDatabasesLocalCloneMapInput interface {
	pulumi.Input

	ToDatabasePluggableDatabasesLocalCloneMapOutput() DatabasePluggableDatabasesLocalCloneMapOutput
	ToDatabasePluggableDatabasesLocalCloneMapOutputWithContext(context.Context) DatabasePluggableDatabasesLocalCloneMapOutput
}

type DatabasePluggableDatabasesLocalCloneMap map[string]DatabasePluggableDatabasesLocalCloneInput

func (DatabasePluggableDatabasesLocalCloneMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DatabasePluggableDatabasesLocalClone)(nil)).Elem()
}

func (i DatabasePluggableDatabasesLocalCloneMap) ToDatabasePluggableDatabasesLocalCloneMapOutput() DatabasePluggableDatabasesLocalCloneMapOutput {
	return i.ToDatabasePluggableDatabasesLocalCloneMapOutputWithContext(context.Background())
}

func (i DatabasePluggableDatabasesLocalCloneMap) ToDatabasePluggableDatabasesLocalCloneMapOutputWithContext(ctx context.Context) DatabasePluggableDatabasesLocalCloneMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabasePluggableDatabasesLocalCloneMapOutput)
}

type DatabasePluggableDatabasesLocalCloneOutput struct {
	*pulumi.OutputState
}

func (DatabasePluggableDatabasesLocalCloneOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*DatabasePluggableDatabasesLocalClone)(nil))
}

func (o DatabasePluggableDatabasesLocalCloneOutput) ToDatabasePluggableDatabasesLocalCloneOutput() DatabasePluggableDatabasesLocalCloneOutput {
	return o
}

func (o DatabasePluggableDatabasesLocalCloneOutput) ToDatabasePluggableDatabasesLocalCloneOutputWithContext(ctx context.Context) DatabasePluggableDatabasesLocalCloneOutput {
	return o
}

func (o DatabasePluggableDatabasesLocalCloneOutput) ToDatabasePluggableDatabasesLocalClonePtrOutput() DatabasePluggableDatabasesLocalClonePtrOutput {
	return o.ToDatabasePluggableDatabasesLocalClonePtrOutputWithContext(context.Background())
}

func (o DatabasePluggableDatabasesLocalCloneOutput) ToDatabasePluggableDatabasesLocalClonePtrOutputWithContext(ctx context.Context) DatabasePluggableDatabasesLocalClonePtrOutput {
	return o.ApplyT(func(v DatabasePluggableDatabasesLocalClone) *DatabasePluggableDatabasesLocalClone {
		return &v
	}).(DatabasePluggableDatabasesLocalClonePtrOutput)
}

type DatabasePluggableDatabasesLocalClonePtrOutput struct {
	*pulumi.OutputState
}

func (DatabasePluggableDatabasesLocalClonePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DatabasePluggableDatabasesLocalClone)(nil))
}

func (o DatabasePluggableDatabasesLocalClonePtrOutput) ToDatabasePluggableDatabasesLocalClonePtrOutput() DatabasePluggableDatabasesLocalClonePtrOutput {
	return o
}

func (o DatabasePluggableDatabasesLocalClonePtrOutput) ToDatabasePluggableDatabasesLocalClonePtrOutputWithContext(ctx context.Context) DatabasePluggableDatabasesLocalClonePtrOutput {
	return o
}

type DatabasePluggableDatabasesLocalCloneArrayOutput struct{ *pulumi.OutputState }

func (DatabasePluggableDatabasesLocalCloneArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]DatabasePluggableDatabasesLocalClone)(nil))
}

func (o DatabasePluggableDatabasesLocalCloneArrayOutput) ToDatabasePluggableDatabasesLocalCloneArrayOutput() DatabasePluggableDatabasesLocalCloneArrayOutput {
	return o
}

func (o DatabasePluggableDatabasesLocalCloneArrayOutput) ToDatabasePluggableDatabasesLocalCloneArrayOutputWithContext(ctx context.Context) DatabasePluggableDatabasesLocalCloneArrayOutput {
	return o
}

func (o DatabasePluggableDatabasesLocalCloneArrayOutput) Index(i pulumi.IntInput) DatabasePluggableDatabasesLocalCloneOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) DatabasePluggableDatabasesLocalClone {
		return vs[0].([]DatabasePluggableDatabasesLocalClone)[vs[1].(int)]
	}).(DatabasePluggableDatabasesLocalCloneOutput)
}

type DatabasePluggableDatabasesLocalCloneMapOutput struct{ *pulumi.OutputState }

func (DatabasePluggableDatabasesLocalCloneMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]DatabasePluggableDatabasesLocalClone)(nil))
}

func (o DatabasePluggableDatabasesLocalCloneMapOutput) ToDatabasePluggableDatabasesLocalCloneMapOutput() DatabasePluggableDatabasesLocalCloneMapOutput {
	return o
}

func (o DatabasePluggableDatabasesLocalCloneMapOutput) ToDatabasePluggableDatabasesLocalCloneMapOutputWithContext(ctx context.Context) DatabasePluggableDatabasesLocalCloneMapOutput {
	return o
}

func (o DatabasePluggableDatabasesLocalCloneMapOutput) MapIndex(k pulumi.StringInput) DatabasePluggableDatabasesLocalCloneOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) DatabasePluggableDatabasesLocalClone {
		return vs[0].(map[string]DatabasePluggableDatabasesLocalClone)[vs[1].(string)]
	}).(DatabasePluggableDatabasesLocalCloneOutput)
}

func init() {
	pulumi.RegisterOutputType(DatabasePluggableDatabasesLocalCloneOutput{})
	pulumi.RegisterOutputType(DatabasePluggableDatabasesLocalClonePtrOutput{})
	pulumi.RegisterOutputType(DatabasePluggableDatabasesLocalCloneArrayOutput{})
	pulumi.RegisterOutputType(DatabasePluggableDatabasesLocalCloneMapOutput{})
}
