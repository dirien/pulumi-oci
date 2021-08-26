// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Key Store resource in Oracle Cloud Infrastructure Database service.
//
// Creates a Key Store.
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
// 		_, err := database.NewKeyStore(ctx, "testKeyStore", &database.KeyStoreArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			DisplayName:   pulumi.Any(_var.Key_store_display_name),
// 			TypeDetails: &database.KeyStoreTypeDetailsArgs{
// 				AdminUsername: pulumi.Any(_var.Key_store_type_details_admin_username),
// 				ConnectionIps: pulumi.Any(_var.Key_store_type_details_connection_ips),
// 				SecretId:      pulumi.Any(oci_vault_secret.Test_secret.Id),
// 				Type:          pulumi.Any(_var.Key_store_type_details_type),
// 				VaultId:       pulumi.Any(oci_kms_vault.Test_vault.Id),
// 			},
// 			DefinedTags: pulumi.Any(_var.Key_store_defined_tags),
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
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
// KeyStores can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:database/keyStore:KeyStore test_key_store "id"
// ```
type KeyStore struct {
	pulumi.CustomResourceState

	// List of databases associated with the key store.
	AssociatedDatabases KeyStoreAssociatedDatabaseArrayOutput `pulumi:"associatedDatabases"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// The user-friendly name for the key store. The name does not need to be unique.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The current state of the key store.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time that the key store was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// (Updatable) Key store type details.
	TypeDetails KeyStoreTypeDetailsOutput `pulumi:"typeDetails"`
}

// NewKeyStore registers a new resource with the given unique name, arguments, and options.
func NewKeyStore(ctx *pulumi.Context,
	name string, args *KeyStoreArgs, opts ...pulumi.ResourceOption) (*KeyStore, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.TypeDetails == nil {
		return nil, errors.New("invalid value for required argument 'TypeDetails'")
	}
	var resource KeyStore
	err := ctx.RegisterResource("oci:database/keyStore:KeyStore", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetKeyStore gets an existing KeyStore resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetKeyStore(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *KeyStoreState, opts ...pulumi.ResourceOption) (*KeyStore, error) {
	var resource KeyStore
	err := ctx.ReadResource("oci:database/keyStore:KeyStore", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering KeyStore resources.
type keyStoreState struct {
	// List of databases associated with the key store.
	AssociatedDatabases []KeyStoreAssociatedDatabase `pulumi:"associatedDatabases"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The user-friendly name for the key store. The name does not need to be unique.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Additional information about the current lifecycle state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The current state of the key store.
	State *string `pulumi:"state"`
	// The date and time that the key store was created.
	TimeCreated *string `pulumi:"timeCreated"`
	// (Updatable) Key store type details.
	TypeDetails *KeyStoreTypeDetails `pulumi:"typeDetails"`
}

type KeyStoreState struct {
	// List of databases associated with the key store.
	AssociatedDatabases KeyStoreAssociatedDatabaseArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.MapInput
	// The user-friendly name for the key store. The name does not need to be unique.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringPtrInput
	// The current state of the key store.
	State pulumi.StringPtrInput
	// The date and time that the key store was created.
	TimeCreated pulumi.StringPtrInput
	// (Updatable) Key store type details.
	TypeDetails KeyStoreTypeDetailsPtrInput
}

func (KeyStoreState) ElementType() reflect.Type {
	return reflect.TypeOf((*keyStoreState)(nil)).Elem()
}

type keyStoreArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The user-friendly name for the key store. The name does not need to be unique.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Key store type details.
	TypeDetails KeyStoreTypeDetails `pulumi:"typeDetails"`
}

// The set of arguments for constructing a KeyStore resource.
type KeyStoreArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.MapInput
	// The user-friendly name for the key store. The name does not need to be unique.
	DisplayName pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Key store type details.
	TypeDetails KeyStoreTypeDetailsInput
}

func (KeyStoreArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*keyStoreArgs)(nil)).Elem()
}

type KeyStoreInput interface {
	pulumi.Input

	ToKeyStoreOutput() KeyStoreOutput
	ToKeyStoreOutputWithContext(ctx context.Context) KeyStoreOutput
}

func (*KeyStore) ElementType() reflect.Type {
	return reflect.TypeOf((*KeyStore)(nil))
}

func (i *KeyStore) ToKeyStoreOutput() KeyStoreOutput {
	return i.ToKeyStoreOutputWithContext(context.Background())
}

func (i *KeyStore) ToKeyStoreOutputWithContext(ctx context.Context) KeyStoreOutput {
	return pulumi.ToOutputWithContext(ctx, i).(KeyStoreOutput)
}

func (i *KeyStore) ToKeyStorePtrOutput() KeyStorePtrOutput {
	return i.ToKeyStorePtrOutputWithContext(context.Background())
}

func (i *KeyStore) ToKeyStorePtrOutputWithContext(ctx context.Context) KeyStorePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(KeyStorePtrOutput)
}

type KeyStorePtrInput interface {
	pulumi.Input

	ToKeyStorePtrOutput() KeyStorePtrOutput
	ToKeyStorePtrOutputWithContext(ctx context.Context) KeyStorePtrOutput
}

type keyStorePtrType KeyStoreArgs

func (*keyStorePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**KeyStore)(nil))
}

func (i *keyStorePtrType) ToKeyStorePtrOutput() KeyStorePtrOutput {
	return i.ToKeyStorePtrOutputWithContext(context.Background())
}

func (i *keyStorePtrType) ToKeyStorePtrOutputWithContext(ctx context.Context) KeyStorePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(KeyStorePtrOutput)
}

// KeyStoreArrayInput is an input type that accepts KeyStoreArray and KeyStoreArrayOutput values.
// You can construct a concrete instance of `KeyStoreArrayInput` via:
//
//          KeyStoreArray{ KeyStoreArgs{...} }
type KeyStoreArrayInput interface {
	pulumi.Input

	ToKeyStoreArrayOutput() KeyStoreArrayOutput
	ToKeyStoreArrayOutputWithContext(context.Context) KeyStoreArrayOutput
}

type KeyStoreArray []KeyStoreInput

func (KeyStoreArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*KeyStore)(nil)).Elem()
}

func (i KeyStoreArray) ToKeyStoreArrayOutput() KeyStoreArrayOutput {
	return i.ToKeyStoreArrayOutputWithContext(context.Background())
}

func (i KeyStoreArray) ToKeyStoreArrayOutputWithContext(ctx context.Context) KeyStoreArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(KeyStoreArrayOutput)
}

// KeyStoreMapInput is an input type that accepts KeyStoreMap and KeyStoreMapOutput values.
// You can construct a concrete instance of `KeyStoreMapInput` via:
//
//          KeyStoreMap{ "key": KeyStoreArgs{...} }
type KeyStoreMapInput interface {
	pulumi.Input

	ToKeyStoreMapOutput() KeyStoreMapOutput
	ToKeyStoreMapOutputWithContext(context.Context) KeyStoreMapOutput
}

type KeyStoreMap map[string]KeyStoreInput

func (KeyStoreMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*KeyStore)(nil)).Elem()
}

func (i KeyStoreMap) ToKeyStoreMapOutput() KeyStoreMapOutput {
	return i.ToKeyStoreMapOutputWithContext(context.Background())
}

func (i KeyStoreMap) ToKeyStoreMapOutputWithContext(ctx context.Context) KeyStoreMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(KeyStoreMapOutput)
}

type KeyStoreOutput struct {
	*pulumi.OutputState
}

func (KeyStoreOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*KeyStore)(nil))
}

func (o KeyStoreOutput) ToKeyStoreOutput() KeyStoreOutput {
	return o
}

func (o KeyStoreOutput) ToKeyStoreOutputWithContext(ctx context.Context) KeyStoreOutput {
	return o
}

func (o KeyStoreOutput) ToKeyStorePtrOutput() KeyStorePtrOutput {
	return o.ToKeyStorePtrOutputWithContext(context.Background())
}

func (o KeyStoreOutput) ToKeyStorePtrOutputWithContext(ctx context.Context) KeyStorePtrOutput {
	return o.ApplyT(func(v KeyStore) *KeyStore {
		return &v
	}).(KeyStorePtrOutput)
}

type KeyStorePtrOutput struct {
	*pulumi.OutputState
}

func (KeyStorePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**KeyStore)(nil))
}

func (o KeyStorePtrOutput) ToKeyStorePtrOutput() KeyStorePtrOutput {
	return o
}

func (o KeyStorePtrOutput) ToKeyStorePtrOutputWithContext(ctx context.Context) KeyStorePtrOutput {
	return o
}

type KeyStoreArrayOutput struct{ *pulumi.OutputState }

func (KeyStoreArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]KeyStore)(nil))
}

func (o KeyStoreArrayOutput) ToKeyStoreArrayOutput() KeyStoreArrayOutput {
	return o
}

func (o KeyStoreArrayOutput) ToKeyStoreArrayOutputWithContext(ctx context.Context) KeyStoreArrayOutput {
	return o
}

func (o KeyStoreArrayOutput) Index(i pulumi.IntInput) KeyStoreOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) KeyStore {
		return vs[0].([]KeyStore)[vs[1].(int)]
	}).(KeyStoreOutput)
}

type KeyStoreMapOutput struct{ *pulumi.OutputState }

func (KeyStoreMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]KeyStore)(nil))
}

func (o KeyStoreMapOutput) ToKeyStoreMapOutput() KeyStoreMapOutput {
	return o
}

func (o KeyStoreMapOutput) ToKeyStoreMapOutputWithContext(ctx context.Context) KeyStoreMapOutput {
	return o
}

func (o KeyStoreMapOutput) MapIndex(k pulumi.StringInput) KeyStoreOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) KeyStore {
		return vs[0].(map[string]KeyStore)[vs[1].(string)]
	}).(KeyStoreOutput)
}

func init() {
	pulumi.RegisterOutputType(KeyStoreOutput{})
	pulumi.RegisterOutputType(KeyStorePtrOutput{})
	pulumi.RegisterOutputType(KeyStoreArrayOutput{})
	pulumi.RegisterOutputType(KeyStoreMapOutput{})
}