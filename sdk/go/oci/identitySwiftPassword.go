// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Swift Password resource in Oracle Cloud Infrastructure Identity service.
//
// **Deprecated. Use [CreateAuthToken](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AuthToken/CreateAuthToken) instead.**
//
// Creates a new Swift password for the specified user. For information about what Swift passwords are for, see
// [Managing User Credentials](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingcredentials.htm).
//
// You must specify a *description* for the Swift password (although it can be an empty string). It does not
// have to be unique, and you can change it anytime with
// [UpdateSwiftPassword](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/SwiftPassword/UpdateSwiftPassword).
//
// Every user has permission to create a Swift password for *their own user ID*. An administrator in your organization
// does not need to write a policy to give users this ability. To compare, administrators who have permission to the
// tenancy can use this operation to create a Swift password for any user, including themselves.
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
// 		_, err := oci.NewIdentitySwiftPassword(ctx, "testSwiftPassword", &oci.IdentitySwiftPasswordArgs{
// 			Description: pulumi.Any(_var.Swift_password_description),
// 			UserId:      pulumi.Any(oci_identity_user.Test_user.Id),
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
// SwiftPasswords can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/identitySwiftPassword:IdentitySwiftPassword test_swift_password "users/{userId}/swiftPasswords/{swiftPasswordId}"
// ```
type IdentitySwiftPassword struct {
	pulumi.CustomResourceState

	// (Updatable) The description you assign to the Swift password during creation. Does not have to be unique, and it's changeable.
	Description pulumi.StringOutput `pulumi:"description"`
	// Date and time when this password will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
	ExpiresOn pulumi.StringOutput `pulumi:"expiresOn"`
	// The detailed status of INACTIVE lifecycleState.
	InactiveState pulumi.StringOutput `pulumi:"inactiveState"`
	// The Swift password. The value is available only in the response for `CreateSwiftPassword`, and not for `ListSwiftPasswords` or `UpdateSwiftPassword`.
	Password pulumi.StringOutput `pulumi:"password"`
	// The password's current state.
	State pulumi.StringOutput `pulumi:"state"`
	// Date and time the `SwiftPassword` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The OCID of the user.
	UserId pulumi.StringOutput `pulumi:"userId"`
}

// NewIdentitySwiftPassword registers a new resource with the given unique name, arguments, and options.
func NewIdentitySwiftPassword(ctx *pulumi.Context,
	name string, args *IdentitySwiftPasswordArgs, opts ...pulumi.ResourceOption) (*IdentitySwiftPassword, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Description == nil {
		return nil, errors.New("invalid value for required argument 'Description'")
	}
	if args.UserId == nil {
		return nil, errors.New("invalid value for required argument 'UserId'")
	}
	var resource IdentitySwiftPassword
	err := ctx.RegisterResource("oci:index/identitySwiftPassword:IdentitySwiftPassword", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetIdentitySwiftPassword gets an existing IdentitySwiftPassword resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetIdentitySwiftPassword(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *IdentitySwiftPasswordState, opts ...pulumi.ResourceOption) (*IdentitySwiftPassword, error) {
	var resource IdentitySwiftPassword
	err := ctx.ReadResource("oci:index/identitySwiftPassword:IdentitySwiftPassword", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering IdentitySwiftPassword resources.
type identitySwiftPasswordState struct {
	// (Updatable) The description you assign to the Swift password during creation. Does not have to be unique, and it's changeable.
	Description *string `pulumi:"description"`
	// Date and time when this password will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
	ExpiresOn *string `pulumi:"expiresOn"`
	// The detailed status of INACTIVE lifecycleState.
	InactiveState *string `pulumi:"inactiveState"`
	// The Swift password. The value is available only in the response for `CreateSwiftPassword`, and not for `ListSwiftPasswords` or `UpdateSwiftPassword`.
	Password *string `pulumi:"password"`
	// The password's current state.
	State *string `pulumi:"state"`
	// Date and time the `SwiftPassword` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The OCID of the user.
	UserId *string `pulumi:"userId"`
}

type IdentitySwiftPasswordState struct {
	// (Updatable) The description you assign to the Swift password during creation. Does not have to be unique, and it's changeable.
	Description pulumi.StringPtrInput
	// Date and time when this password will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
	ExpiresOn pulumi.StringPtrInput
	// The detailed status of INACTIVE lifecycleState.
	InactiveState pulumi.StringPtrInput
	// The Swift password. The value is available only in the response for `CreateSwiftPassword`, and not for `ListSwiftPasswords` or `UpdateSwiftPassword`.
	Password pulumi.StringPtrInput
	// The password's current state.
	State pulumi.StringPtrInput
	// Date and time the `SwiftPassword` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The OCID of the user.
	UserId pulumi.StringPtrInput
}

func (IdentitySwiftPasswordState) ElementType() reflect.Type {
	return reflect.TypeOf((*identitySwiftPasswordState)(nil)).Elem()
}

type identitySwiftPasswordArgs struct {
	// (Updatable) The description you assign to the Swift password during creation. Does not have to be unique, and it's changeable.
	Description string `pulumi:"description"`
	// The OCID of the user.
	UserId string `pulumi:"userId"`
}

// The set of arguments for constructing a IdentitySwiftPassword resource.
type IdentitySwiftPasswordArgs struct {
	// (Updatable) The description you assign to the Swift password during creation. Does not have to be unique, and it's changeable.
	Description pulumi.StringInput
	// The OCID of the user.
	UserId pulumi.StringInput
}

func (IdentitySwiftPasswordArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*identitySwiftPasswordArgs)(nil)).Elem()
}

type IdentitySwiftPasswordInput interface {
	pulumi.Input

	ToIdentitySwiftPasswordOutput() IdentitySwiftPasswordOutput
	ToIdentitySwiftPasswordOutputWithContext(ctx context.Context) IdentitySwiftPasswordOutput
}

func (*IdentitySwiftPassword) ElementType() reflect.Type {
	return reflect.TypeOf((*IdentitySwiftPassword)(nil))
}

func (i *IdentitySwiftPassword) ToIdentitySwiftPasswordOutput() IdentitySwiftPasswordOutput {
	return i.ToIdentitySwiftPasswordOutputWithContext(context.Background())
}

func (i *IdentitySwiftPassword) ToIdentitySwiftPasswordOutputWithContext(ctx context.Context) IdentitySwiftPasswordOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IdentitySwiftPasswordOutput)
}

func (i *IdentitySwiftPassword) ToIdentitySwiftPasswordPtrOutput() IdentitySwiftPasswordPtrOutput {
	return i.ToIdentitySwiftPasswordPtrOutputWithContext(context.Background())
}

func (i *IdentitySwiftPassword) ToIdentitySwiftPasswordPtrOutputWithContext(ctx context.Context) IdentitySwiftPasswordPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IdentitySwiftPasswordPtrOutput)
}

type IdentitySwiftPasswordPtrInput interface {
	pulumi.Input

	ToIdentitySwiftPasswordPtrOutput() IdentitySwiftPasswordPtrOutput
	ToIdentitySwiftPasswordPtrOutputWithContext(ctx context.Context) IdentitySwiftPasswordPtrOutput
}

type identitySwiftPasswordPtrType IdentitySwiftPasswordArgs

func (*identitySwiftPasswordPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**IdentitySwiftPassword)(nil))
}

func (i *identitySwiftPasswordPtrType) ToIdentitySwiftPasswordPtrOutput() IdentitySwiftPasswordPtrOutput {
	return i.ToIdentitySwiftPasswordPtrOutputWithContext(context.Background())
}

func (i *identitySwiftPasswordPtrType) ToIdentitySwiftPasswordPtrOutputWithContext(ctx context.Context) IdentitySwiftPasswordPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IdentitySwiftPasswordPtrOutput)
}

// IdentitySwiftPasswordArrayInput is an input type that accepts IdentitySwiftPasswordArray and IdentitySwiftPasswordArrayOutput values.
// You can construct a concrete instance of `IdentitySwiftPasswordArrayInput` via:
//
//          IdentitySwiftPasswordArray{ IdentitySwiftPasswordArgs{...} }
type IdentitySwiftPasswordArrayInput interface {
	pulumi.Input

	ToIdentitySwiftPasswordArrayOutput() IdentitySwiftPasswordArrayOutput
	ToIdentitySwiftPasswordArrayOutputWithContext(context.Context) IdentitySwiftPasswordArrayOutput
}

type IdentitySwiftPasswordArray []IdentitySwiftPasswordInput

func (IdentitySwiftPasswordArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*IdentitySwiftPassword)(nil)).Elem()
}

func (i IdentitySwiftPasswordArray) ToIdentitySwiftPasswordArrayOutput() IdentitySwiftPasswordArrayOutput {
	return i.ToIdentitySwiftPasswordArrayOutputWithContext(context.Background())
}

func (i IdentitySwiftPasswordArray) ToIdentitySwiftPasswordArrayOutputWithContext(ctx context.Context) IdentitySwiftPasswordArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IdentitySwiftPasswordArrayOutput)
}

// IdentitySwiftPasswordMapInput is an input type that accepts IdentitySwiftPasswordMap and IdentitySwiftPasswordMapOutput values.
// You can construct a concrete instance of `IdentitySwiftPasswordMapInput` via:
//
//          IdentitySwiftPasswordMap{ "key": IdentitySwiftPasswordArgs{...} }
type IdentitySwiftPasswordMapInput interface {
	pulumi.Input

	ToIdentitySwiftPasswordMapOutput() IdentitySwiftPasswordMapOutput
	ToIdentitySwiftPasswordMapOutputWithContext(context.Context) IdentitySwiftPasswordMapOutput
}

type IdentitySwiftPasswordMap map[string]IdentitySwiftPasswordInput

func (IdentitySwiftPasswordMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*IdentitySwiftPassword)(nil)).Elem()
}

func (i IdentitySwiftPasswordMap) ToIdentitySwiftPasswordMapOutput() IdentitySwiftPasswordMapOutput {
	return i.ToIdentitySwiftPasswordMapOutputWithContext(context.Background())
}

func (i IdentitySwiftPasswordMap) ToIdentitySwiftPasswordMapOutputWithContext(ctx context.Context) IdentitySwiftPasswordMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IdentitySwiftPasswordMapOutput)
}

type IdentitySwiftPasswordOutput struct {
	*pulumi.OutputState
}

func (IdentitySwiftPasswordOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*IdentitySwiftPassword)(nil))
}

func (o IdentitySwiftPasswordOutput) ToIdentitySwiftPasswordOutput() IdentitySwiftPasswordOutput {
	return o
}

func (o IdentitySwiftPasswordOutput) ToIdentitySwiftPasswordOutputWithContext(ctx context.Context) IdentitySwiftPasswordOutput {
	return o
}

func (o IdentitySwiftPasswordOutput) ToIdentitySwiftPasswordPtrOutput() IdentitySwiftPasswordPtrOutput {
	return o.ToIdentitySwiftPasswordPtrOutputWithContext(context.Background())
}

func (o IdentitySwiftPasswordOutput) ToIdentitySwiftPasswordPtrOutputWithContext(ctx context.Context) IdentitySwiftPasswordPtrOutput {
	return o.ApplyT(func(v IdentitySwiftPassword) *IdentitySwiftPassword {
		return &v
	}).(IdentitySwiftPasswordPtrOutput)
}

type IdentitySwiftPasswordPtrOutput struct {
	*pulumi.OutputState
}

func (IdentitySwiftPasswordPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**IdentitySwiftPassword)(nil))
}

func (o IdentitySwiftPasswordPtrOutput) ToIdentitySwiftPasswordPtrOutput() IdentitySwiftPasswordPtrOutput {
	return o
}

func (o IdentitySwiftPasswordPtrOutput) ToIdentitySwiftPasswordPtrOutputWithContext(ctx context.Context) IdentitySwiftPasswordPtrOutput {
	return o
}

type IdentitySwiftPasswordArrayOutput struct{ *pulumi.OutputState }

func (IdentitySwiftPasswordArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]IdentitySwiftPassword)(nil))
}

func (o IdentitySwiftPasswordArrayOutput) ToIdentitySwiftPasswordArrayOutput() IdentitySwiftPasswordArrayOutput {
	return o
}

func (o IdentitySwiftPasswordArrayOutput) ToIdentitySwiftPasswordArrayOutputWithContext(ctx context.Context) IdentitySwiftPasswordArrayOutput {
	return o
}

func (o IdentitySwiftPasswordArrayOutput) Index(i pulumi.IntInput) IdentitySwiftPasswordOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) IdentitySwiftPassword {
		return vs[0].([]IdentitySwiftPassword)[vs[1].(int)]
	}).(IdentitySwiftPasswordOutput)
}

type IdentitySwiftPasswordMapOutput struct{ *pulumi.OutputState }

func (IdentitySwiftPasswordMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]IdentitySwiftPassword)(nil))
}

func (o IdentitySwiftPasswordMapOutput) ToIdentitySwiftPasswordMapOutput() IdentitySwiftPasswordMapOutput {
	return o
}

func (o IdentitySwiftPasswordMapOutput) ToIdentitySwiftPasswordMapOutputWithContext(ctx context.Context) IdentitySwiftPasswordMapOutput {
	return o
}

func (o IdentitySwiftPasswordMapOutput) MapIndex(k pulumi.StringInput) IdentitySwiftPasswordOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) IdentitySwiftPassword {
		return vs[0].(map[string]IdentitySwiftPassword)[vs[1].(string)]
	}).(IdentitySwiftPasswordOutput)
}

func init() {
	pulumi.RegisterOutputType(IdentitySwiftPasswordOutput{})
	pulumi.RegisterOutputType(IdentitySwiftPasswordPtrOutput{})
	pulumi.RegisterOutputType(IdentitySwiftPasswordArrayOutput{})
	pulumi.RegisterOutputType(IdentitySwiftPasswordMapOutput{})
}