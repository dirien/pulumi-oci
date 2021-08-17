// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the User resource in Oracle Cloud Infrastructure Identity service.
//
// Creates a new user in your tenancy. For conceptual information about users, your tenancy, and other
// IAM Service components, see [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
//
// You must specify your tenancy's OCID as the compartment ID in the request object (remember that the
// tenancy is simply the root compartment). Notice that IAM resources (users, groups, compartments, and
// some policies) reside within the tenancy itself, unlike cloud resources such as compute instances,
// which typically reside within compartments inside the tenancy. For information about OCIDs, see
// [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
//
// You must also specify a *name* for the user, which must be unique across all users in your tenancy
// and cannot be changed. Allowed characters: No spaces. Only letters, numerals, hyphens, periods,
// underscores, +, and @. If you specify a name that's already in use, you'll get a 409 error.
// This name will be the user's login to the Console. You might want to pick a
// name that your company's own identity system (e.g., Active Directory, LDAP, etc.) already uses.
// If you delete a user and then create a new user with the same name, they'll be considered different
// users because they have different OCIDs.
//
// You must also specify a *description* for the user (although it can be an empty string).
// It does not have to be unique, and you can change it anytime with
// [UpdateUser](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/User/UpdateUser). You can use the field to provide the user's
// full name, a description, a nickname, or other information to generally identify the user.
// A new user has no permissions until you place the user in one or more groups (see
// [AddUserToGroup](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/UserGroupMembership/AddUserToGroup)). If the user needs to
// access the Console, you need to provide the user a password (see
// [CreateOrResetUIPassword](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/UIPassword/CreateOrResetUIPassword)).
// If the user needs to access the Oracle Cloud Infrastructure REST API, you need to upload a
// public API signing key for that user (see
// [Required Keys and OCIDs](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm) and also
// [UploadApiKey](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/ApiKey/UploadApiKey)).
//
// **Important:** Make sure to inform the new user which compartment(s) they have access to.
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
// 		_, err := oci.NewIdentityUser(ctx, "testUser", &oci.IdentityUserArgs{
// 			CompartmentId: pulumi.Any(_var.Tenancy_ocid),
// 			Description:   pulumi.Any(_var.User_description),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			Email: pulumi.Any(_var.User_email),
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
// Users can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/identityUser:IdentityUser test_user "id"
// ```
type IdentityUser struct {
	pulumi.CustomResourceState

	// Properties indicating how the user is allowed to authenticate.
	Capabilities IdentityUserCapabilitiesOutput `pulumi:"capabilities"`
	// The OCID of the tenancy containing the user.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) The description you assign to the user during creation. Does not have to be unique, and it's changeable.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The email you assign to the user. Has to be unique across the tenancy.
	Email pulumi.StringOutput `pulumi:"email"`
	// Whether the email address has been validated.
	EmailVerified pulumi.BoolOutput `pulumi:"emailVerified"`
	// Identifier of the user in the identity provider
	ExternalIdentifier pulumi.StringOutput `pulumi:"externalIdentifier"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The OCID of the `IdentityProvider` this user belongs to.
	IdentityProviderId pulumi.StringOutput `pulumi:"identityProviderId"`
	// Returned only if the user's `lifecycleState` is INACTIVE. A 16-bit value showing the reason why the user is inactive:
	// * bit 0: SUSPENDED (reserved for future use)
	// * bit 1: DISABLED (reserved for future use)
	// * bit 2: BLOCKED (the user has exceeded the maximum number of failed login attempts for the Console)
	InactiveState pulumi.StringOutput `pulumi:"inactiveState"`
	// The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
	LastSuccessfulLoginTime pulumi.StringOutput `pulumi:"lastSuccessfulLoginTime"`
	// The name you assign to the user during creation. This is the user's login for the Console. The name must be unique across all users in the tenancy and cannot be changed.
	Name pulumi.StringOutput `pulumi:"name"`
	// The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
	PreviousSuccessfulLoginTime pulumi.StringOutput `pulumi:"previousSuccessfulLoginTime"`
	// The user's current state.
	State pulumi.StringOutput `pulumi:"state"`
	// Date and time the user was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewIdentityUser registers a new resource with the given unique name, arguments, and options.
func NewIdentityUser(ctx *pulumi.Context,
	name string, args *IdentityUserArgs, opts ...pulumi.ResourceOption) (*IdentityUser, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Description == nil {
		return nil, errors.New("invalid value for required argument 'Description'")
	}
	var resource IdentityUser
	err := ctx.RegisterResource("oci:index/identityUser:IdentityUser", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetIdentityUser gets an existing IdentityUser resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetIdentityUser(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *IdentityUserState, opts ...pulumi.ResourceOption) (*IdentityUser, error) {
	var resource IdentityUser
	err := ctx.ReadResource("oci:index/identityUser:IdentityUser", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering IdentityUser resources.
type identityUserState struct {
	// Properties indicating how the user is allowed to authenticate.
	Capabilities *IdentityUserCapabilities `pulumi:"capabilities"`
	// The OCID of the tenancy containing the user.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description you assign to the user during creation. Does not have to be unique, and it's changeable.
	Description *string `pulumi:"description"`
	// (Updatable) The email you assign to the user. Has to be unique across the tenancy.
	Email *string `pulumi:"email"`
	// Whether the email address has been validated.
	EmailVerified *bool `pulumi:"emailVerified"`
	// Identifier of the user in the identity provider
	ExternalIdentifier *string `pulumi:"externalIdentifier"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the `IdentityProvider` this user belongs to.
	IdentityProviderId *string `pulumi:"identityProviderId"`
	// Returned only if the user's `lifecycleState` is INACTIVE. A 16-bit value showing the reason why the user is inactive:
	// * bit 0: SUSPENDED (reserved for future use)
	// * bit 1: DISABLED (reserved for future use)
	// * bit 2: BLOCKED (the user has exceeded the maximum number of failed login attempts for the Console)
	InactiveState *string `pulumi:"inactiveState"`
	// The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
	LastSuccessfulLoginTime *string `pulumi:"lastSuccessfulLoginTime"`
	// The name you assign to the user during creation. This is the user's login for the Console. The name must be unique across all users in the tenancy and cannot be changed.
	Name *string `pulumi:"name"`
	// The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
	PreviousSuccessfulLoginTime *string `pulumi:"previousSuccessfulLoginTime"`
	// The user's current state.
	State *string `pulumi:"state"`
	// Date and time the user was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type IdentityUserState struct {
	// Properties indicating how the user is allowed to authenticate.
	Capabilities IdentityUserCapabilitiesPtrInput
	// The OCID of the tenancy containing the user.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description you assign to the user during creation. Does not have to be unique, and it's changeable.
	Description pulumi.StringPtrInput
	// (Updatable) The email you assign to the user. Has to be unique across the tenancy.
	Email pulumi.StringPtrInput
	// Whether the email address has been validated.
	EmailVerified pulumi.BoolPtrInput
	// Identifier of the user in the identity provider
	ExternalIdentifier pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The OCID of the `IdentityProvider` this user belongs to.
	IdentityProviderId pulumi.StringPtrInput
	// Returned only if the user's `lifecycleState` is INACTIVE. A 16-bit value showing the reason why the user is inactive:
	// * bit 0: SUSPENDED (reserved for future use)
	// * bit 1: DISABLED (reserved for future use)
	// * bit 2: BLOCKED (the user has exceeded the maximum number of failed login attempts for the Console)
	InactiveState pulumi.StringPtrInput
	// The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
	LastSuccessfulLoginTime pulumi.StringPtrInput
	// The name you assign to the user during creation. This is the user's login for the Console. The name must be unique across all users in the tenancy and cannot be changed.
	Name pulumi.StringPtrInput
	// The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
	PreviousSuccessfulLoginTime pulumi.StringPtrInput
	// The user's current state.
	State pulumi.StringPtrInput
	// Date and time the user was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (IdentityUserState) ElementType() reflect.Type {
	return reflect.TypeOf((*identityUserState)(nil)).Elem()
}

type identityUserArgs struct {
	// The OCID of the tenancy containing the user.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description you assign to the user during creation. Does not have to be unique, and it's changeable.
	Description string `pulumi:"description"`
	// (Updatable) The email you assign to the user. Has to be unique across the tenancy.
	Email *string `pulumi:"email"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The name you assign to the user during creation. This is the user's login for the Console. The name must be unique across all users in the tenancy and cannot be changed.
	Name *string `pulumi:"name"`
}

// The set of arguments for constructing a IdentityUser resource.
type IdentityUserArgs struct {
	// The OCID of the tenancy containing the user.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description you assign to the user during creation. Does not have to be unique, and it's changeable.
	Description pulumi.StringInput
	// (Updatable) The email you assign to the user. Has to be unique across the tenancy.
	Email pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The name you assign to the user during creation. This is the user's login for the Console. The name must be unique across all users in the tenancy and cannot be changed.
	Name pulumi.StringPtrInput
}

func (IdentityUserArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*identityUserArgs)(nil)).Elem()
}

type IdentityUserInput interface {
	pulumi.Input

	ToIdentityUserOutput() IdentityUserOutput
	ToIdentityUserOutputWithContext(ctx context.Context) IdentityUserOutput
}

func (*IdentityUser) ElementType() reflect.Type {
	return reflect.TypeOf((*IdentityUser)(nil))
}

func (i *IdentityUser) ToIdentityUserOutput() IdentityUserOutput {
	return i.ToIdentityUserOutputWithContext(context.Background())
}

func (i *IdentityUser) ToIdentityUserOutputWithContext(ctx context.Context) IdentityUserOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IdentityUserOutput)
}

func (i *IdentityUser) ToIdentityUserPtrOutput() IdentityUserPtrOutput {
	return i.ToIdentityUserPtrOutputWithContext(context.Background())
}

func (i *IdentityUser) ToIdentityUserPtrOutputWithContext(ctx context.Context) IdentityUserPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IdentityUserPtrOutput)
}

type IdentityUserPtrInput interface {
	pulumi.Input

	ToIdentityUserPtrOutput() IdentityUserPtrOutput
	ToIdentityUserPtrOutputWithContext(ctx context.Context) IdentityUserPtrOutput
}

type identityUserPtrType IdentityUserArgs

func (*identityUserPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**IdentityUser)(nil))
}

func (i *identityUserPtrType) ToIdentityUserPtrOutput() IdentityUserPtrOutput {
	return i.ToIdentityUserPtrOutputWithContext(context.Background())
}

func (i *identityUserPtrType) ToIdentityUserPtrOutputWithContext(ctx context.Context) IdentityUserPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IdentityUserPtrOutput)
}

// IdentityUserArrayInput is an input type that accepts IdentityUserArray and IdentityUserArrayOutput values.
// You can construct a concrete instance of `IdentityUserArrayInput` via:
//
//          IdentityUserArray{ IdentityUserArgs{...} }
type IdentityUserArrayInput interface {
	pulumi.Input

	ToIdentityUserArrayOutput() IdentityUserArrayOutput
	ToIdentityUserArrayOutputWithContext(context.Context) IdentityUserArrayOutput
}

type IdentityUserArray []IdentityUserInput

func (IdentityUserArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*IdentityUser)(nil)).Elem()
}

func (i IdentityUserArray) ToIdentityUserArrayOutput() IdentityUserArrayOutput {
	return i.ToIdentityUserArrayOutputWithContext(context.Background())
}

func (i IdentityUserArray) ToIdentityUserArrayOutputWithContext(ctx context.Context) IdentityUserArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IdentityUserArrayOutput)
}

// IdentityUserMapInput is an input type that accepts IdentityUserMap and IdentityUserMapOutput values.
// You can construct a concrete instance of `IdentityUserMapInput` via:
//
//          IdentityUserMap{ "key": IdentityUserArgs{...} }
type IdentityUserMapInput interface {
	pulumi.Input

	ToIdentityUserMapOutput() IdentityUserMapOutput
	ToIdentityUserMapOutputWithContext(context.Context) IdentityUserMapOutput
}

type IdentityUserMap map[string]IdentityUserInput

func (IdentityUserMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*IdentityUser)(nil)).Elem()
}

func (i IdentityUserMap) ToIdentityUserMapOutput() IdentityUserMapOutput {
	return i.ToIdentityUserMapOutputWithContext(context.Background())
}

func (i IdentityUserMap) ToIdentityUserMapOutputWithContext(ctx context.Context) IdentityUserMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IdentityUserMapOutput)
}

type IdentityUserOutput struct {
	*pulumi.OutputState
}

func (IdentityUserOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*IdentityUser)(nil))
}

func (o IdentityUserOutput) ToIdentityUserOutput() IdentityUserOutput {
	return o
}

func (o IdentityUserOutput) ToIdentityUserOutputWithContext(ctx context.Context) IdentityUserOutput {
	return o
}

func (o IdentityUserOutput) ToIdentityUserPtrOutput() IdentityUserPtrOutput {
	return o.ToIdentityUserPtrOutputWithContext(context.Background())
}

func (o IdentityUserOutput) ToIdentityUserPtrOutputWithContext(ctx context.Context) IdentityUserPtrOutput {
	return o.ApplyT(func(v IdentityUser) *IdentityUser {
		return &v
	}).(IdentityUserPtrOutput)
}

type IdentityUserPtrOutput struct {
	*pulumi.OutputState
}

func (IdentityUserPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**IdentityUser)(nil))
}

func (o IdentityUserPtrOutput) ToIdentityUserPtrOutput() IdentityUserPtrOutput {
	return o
}

func (o IdentityUserPtrOutput) ToIdentityUserPtrOutputWithContext(ctx context.Context) IdentityUserPtrOutput {
	return o
}

type IdentityUserArrayOutput struct{ *pulumi.OutputState }

func (IdentityUserArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]IdentityUser)(nil))
}

func (o IdentityUserArrayOutput) ToIdentityUserArrayOutput() IdentityUserArrayOutput {
	return o
}

func (o IdentityUserArrayOutput) ToIdentityUserArrayOutputWithContext(ctx context.Context) IdentityUserArrayOutput {
	return o
}

func (o IdentityUserArrayOutput) Index(i pulumi.IntInput) IdentityUserOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) IdentityUser {
		return vs[0].([]IdentityUser)[vs[1].(int)]
	}).(IdentityUserOutput)
}

type IdentityUserMapOutput struct{ *pulumi.OutputState }

func (IdentityUserMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]IdentityUser)(nil))
}

func (o IdentityUserMapOutput) ToIdentityUserMapOutput() IdentityUserMapOutput {
	return o
}

func (o IdentityUserMapOutput) ToIdentityUserMapOutputWithContext(ctx context.Context) IdentityUserMapOutput {
	return o
}

func (o IdentityUserMapOutput) MapIndex(k pulumi.StringInput) IdentityUserOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) IdentityUser {
		return vs[0].(map[string]IdentityUser)[vs[1].(string)]
	}).(IdentityUserOutput)
}

func init() {
	pulumi.RegisterOutputType(IdentityUserOutput{})
	pulumi.RegisterOutputType(IdentityUserPtrOutput{})
	pulumi.RegisterOutputType(IdentityUserArrayOutput{})
	pulumi.RegisterOutputType(IdentityUserMapOutput{})
}