// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package servicecatalog

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Private Application resource in Oracle Cloud Infrastructure Service Catalog service.
//
// Creates a private application along with a single package to be hosted.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/servicecatalog"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := servicecatalog.NewPrivateApplication(ctx, "testPrivateApplication", &servicecatalog.PrivateApplicationArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			DisplayName:   pulumi.Any(_var.Private_application_display_name),
// 			PackageDetails: &servicecatalog.PrivateApplicationPackageDetailsArgs{
// 				PackageType:          pulumi.Any(_var.Private_application_package_details_package_type),
// 				Version:              pulumi.Any(_var.Private_application_package_details_version),
// 				ZipFileBase64encoded: pulumi.Any(_var.Private_application_package_details_zip_file_base64encoded),
// 			},
// 			ShortDescription: pulumi.Any(_var.Private_application_short_description),
// 			DefinedTags: pulumi.AnyMap{
// 				"foo-namespace.bar-key": pulumi.Any("value"),
// 			},
// 			FreeformTags: pulumi.AnyMap{
// 				"bar-key": pulumi.Any("value"),
// 			},
// 			LogoFileBase64encoded: pulumi.Any(_var.Private_application_logo_file_base64encoded),
// 			LongDescription:       pulumi.Any(_var.Private_application_long_description),
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
// PrivateApplications can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:servicecatalog/privateApplication:PrivateApplication test_private_application "id"
// ```
type PrivateApplication struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) The name of the private application.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The model for uploaded binary data, like logos and images.
	Logo PrivateApplicationLogoOutput `pulumi:"logo"`
	// (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
	LogoFileBase64encoded pulumi.StringOutput `pulumi:"logoFileBase64encoded"`
	// (Updatable) A long description of the private application.
	LongDescription pulumi.StringOutput `pulumi:"longDescription"`
	// A base object for creating a private application package.
	PackageDetails PrivateApplicationPackageDetailsOutput `pulumi:"packageDetails"`
	// The package's type.
	PackageType pulumi.StringOutput `pulumi:"packageType"`
	// (Updatable) A short description of the private application.
	ShortDescription pulumi.StringOutput `pulumi:"shortDescription"`
	// The lifecycle state of the private application.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewPrivateApplication registers a new resource with the given unique name, arguments, and options.
func NewPrivateApplication(ctx *pulumi.Context,
	name string, args *PrivateApplicationArgs, opts ...pulumi.ResourceOption) (*PrivateApplication, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.PackageDetails == nil {
		return nil, errors.New("invalid value for required argument 'PackageDetails'")
	}
	if args.ShortDescription == nil {
		return nil, errors.New("invalid value for required argument 'ShortDescription'")
	}
	var resource PrivateApplication
	err := ctx.RegisterResource("oci:servicecatalog/privateApplication:PrivateApplication", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPrivateApplication gets an existing PrivateApplication resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPrivateApplication(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PrivateApplicationState, opts ...pulumi.ResourceOption) (*PrivateApplication, error) {
	var resource PrivateApplication
	err := ctx.ReadResource("oci:servicecatalog/privateApplication:PrivateApplication", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PrivateApplication resources.
type privateApplicationState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The name of the private application.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The model for uploaded binary data, like logos and images.
	Logo *PrivateApplicationLogo `pulumi:"logo"`
	// (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
	LogoFileBase64encoded *string `pulumi:"logoFileBase64encoded"`
	// (Updatable) A long description of the private application.
	LongDescription *string `pulumi:"longDescription"`
	// A base object for creating a private application package.
	PackageDetails *PrivateApplicationPackageDetails `pulumi:"packageDetails"`
	// The package's type.
	PackageType *string `pulumi:"packageType"`
	// (Updatable) A short description of the private application.
	ShortDescription *string `pulumi:"shortDescription"`
	// The lifecycle state of the private application.
	State *string `pulumi:"state"`
	// The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type PrivateApplicationState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The name of the private application.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// The model for uploaded binary data, like logos and images.
	Logo PrivateApplicationLogoPtrInput
	// (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
	LogoFileBase64encoded pulumi.StringPtrInput
	// (Updatable) A long description of the private application.
	LongDescription pulumi.StringPtrInput
	// A base object for creating a private application package.
	PackageDetails PrivateApplicationPackageDetailsPtrInput
	// The package's type.
	PackageType pulumi.StringPtrInput
	// (Updatable) A short description of the private application.
	ShortDescription pulumi.StringPtrInput
	// The lifecycle state of the private application.
	State pulumi.StringPtrInput
	// The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
	TimeUpdated pulumi.StringPtrInput
}

func (PrivateApplicationState) ElementType() reflect.Type {
	return reflect.TypeOf((*privateApplicationState)(nil)).Elem()
}

type privateApplicationArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The name of the private application.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
	LogoFileBase64encoded *string `pulumi:"logoFileBase64encoded"`
	// (Updatable) A long description of the private application.
	LongDescription *string `pulumi:"longDescription"`
	// A base object for creating a private application package.
	PackageDetails PrivateApplicationPackageDetails `pulumi:"packageDetails"`
	// (Updatable) A short description of the private application.
	ShortDescription string `pulumi:"shortDescription"`
}

// The set of arguments for constructing a PrivateApplication resource.
type PrivateApplicationArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The name of the private application.
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
	LogoFileBase64encoded pulumi.StringPtrInput
	// (Updatable) A long description of the private application.
	LongDescription pulumi.StringPtrInput
	// A base object for creating a private application package.
	PackageDetails PrivateApplicationPackageDetailsInput
	// (Updatable) A short description of the private application.
	ShortDescription pulumi.StringInput
}

func (PrivateApplicationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*privateApplicationArgs)(nil)).Elem()
}

type PrivateApplicationInput interface {
	pulumi.Input

	ToPrivateApplicationOutput() PrivateApplicationOutput
	ToPrivateApplicationOutputWithContext(ctx context.Context) PrivateApplicationOutput
}

func (*PrivateApplication) ElementType() reflect.Type {
	return reflect.TypeOf((*PrivateApplication)(nil))
}

func (i *PrivateApplication) ToPrivateApplicationOutput() PrivateApplicationOutput {
	return i.ToPrivateApplicationOutputWithContext(context.Background())
}

func (i *PrivateApplication) ToPrivateApplicationOutputWithContext(ctx context.Context) PrivateApplicationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PrivateApplicationOutput)
}

func (i *PrivateApplication) ToPrivateApplicationPtrOutput() PrivateApplicationPtrOutput {
	return i.ToPrivateApplicationPtrOutputWithContext(context.Background())
}

func (i *PrivateApplication) ToPrivateApplicationPtrOutputWithContext(ctx context.Context) PrivateApplicationPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PrivateApplicationPtrOutput)
}

type PrivateApplicationPtrInput interface {
	pulumi.Input

	ToPrivateApplicationPtrOutput() PrivateApplicationPtrOutput
	ToPrivateApplicationPtrOutputWithContext(ctx context.Context) PrivateApplicationPtrOutput
}

type privateApplicationPtrType PrivateApplicationArgs

func (*privateApplicationPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**PrivateApplication)(nil))
}

func (i *privateApplicationPtrType) ToPrivateApplicationPtrOutput() PrivateApplicationPtrOutput {
	return i.ToPrivateApplicationPtrOutputWithContext(context.Background())
}

func (i *privateApplicationPtrType) ToPrivateApplicationPtrOutputWithContext(ctx context.Context) PrivateApplicationPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PrivateApplicationPtrOutput)
}

// PrivateApplicationArrayInput is an input type that accepts PrivateApplicationArray and PrivateApplicationArrayOutput values.
// You can construct a concrete instance of `PrivateApplicationArrayInput` via:
//
//          PrivateApplicationArray{ PrivateApplicationArgs{...} }
type PrivateApplicationArrayInput interface {
	pulumi.Input

	ToPrivateApplicationArrayOutput() PrivateApplicationArrayOutput
	ToPrivateApplicationArrayOutputWithContext(context.Context) PrivateApplicationArrayOutput
}

type PrivateApplicationArray []PrivateApplicationInput

func (PrivateApplicationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*PrivateApplication)(nil)).Elem()
}

func (i PrivateApplicationArray) ToPrivateApplicationArrayOutput() PrivateApplicationArrayOutput {
	return i.ToPrivateApplicationArrayOutputWithContext(context.Background())
}

func (i PrivateApplicationArray) ToPrivateApplicationArrayOutputWithContext(ctx context.Context) PrivateApplicationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PrivateApplicationArrayOutput)
}

// PrivateApplicationMapInput is an input type that accepts PrivateApplicationMap and PrivateApplicationMapOutput values.
// You can construct a concrete instance of `PrivateApplicationMapInput` via:
//
//          PrivateApplicationMap{ "key": PrivateApplicationArgs{...} }
type PrivateApplicationMapInput interface {
	pulumi.Input

	ToPrivateApplicationMapOutput() PrivateApplicationMapOutput
	ToPrivateApplicationMapOutputWithContext(context.Context) PrivateApplicationMapOutput
}

type PrivateApplicationMap map[string]PrivateApplicationInput

func (PrivateApplicationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*PrivateApplication)(nil)).Elem()
}

func (i PrivateApplicationMap) ToPrivateApplicationMapOutput() PrivateApplicationMapOutput {
	return i.ToPrivateApplicationMapOutputWithContext(context.Background())
}

func (i PrivateApplicationMap) ToPrivateApplicationMapOutputWithContext(ctx context.Context) PrivateApplicationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PrivateApplicationMapOutput)
}

type PrivateApplicationOutput struct {
	*pulumi.OutputState
}

func (PrivateApplicationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*PrivateApplication)(nil))
}

func (o PrivateApplicationOutput) ToPrivateApplicationOutput() PrivateApplicationOutput {
	return o
}

func (o PrivateApplicationOutput) ToPrivateApplicationOutputWithContext(ctx context.Context) PrivateApplicationOutput {
	return o
}

func (o PrivateApplicationOutput) ToPrivateApplicationPtrOutput() PrivateApplicationPtrOutput {
	return o.ToPrivateApplicationPtrOutputWithContext(context.Background())
}

func (o PrivateApplicationOutput) ToPrivateApplicationPtrOutputWithContext(ctx context.Context) PrivateApplicationPtrOutput {
	return o.ApplyT(func(v PrivateApplication) *PrivateApplication {
		return &v
	}).(PrivateApplicationPtrOutput)
}

type PrivateApplicationPtrOutput struct {
	*pulumi.OutputState
}

func (PrivateApplicationPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**PrivateApplication)(nil))
}

func (o PrivateApplicationPtrOutput) ToPrivateApplicationPtrOutput() PrivateApplicationPtrOutput {
	return o
}

func (o PrivateApplicationPtrOutput) ToPrivateApplicationPtrOutputWithContext(ctx context.Context) PrivateApplicationPtrOutput {
	return o
}

type PrivateApplicationArrayOutput struct{ *pulumi.OutputState }

func (PrivateApplicationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]PrivateApplication)(nil))
}

func (o PrivateApplicationArrayOutput) ToPrivateApplicationArrayOutput() PrivateApplicationArrayOutput {
	return o
}

func (o PrivateApplicationArrayOutput) ToPrivateApplicationArrayOutputWithContext(ctx context.Context) PrivateApplicationArrayOutput {
	return o
}

func (o PrivateApplicationArrayOutput) Index(i pulumi.IntInput) PrivateApplicationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) PrivateApplication {
		return vs[0].([]PrivateApplication)[vs[1].(int)]
	}).(PrivateApplicationOutput)
}

type PrivateApplicationMapOutput struct{ *pulumi.OutputState }

func (PrivateApplicationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]PrivateApplication)(nil))
}

func (o PrivateApplicationMapOutput) ToPrivateApplicationMapOutput() PrivateApplicationMapOutput {
	return o
}

func (o PrivateApplicationMapOutput) ToPrivateApplicationMapOutputWithContext(ctx context.Context) PrivateApplicationMapOutput {
	return o
}

func (o PrivateApplicationMapOutput) MapIndex(k pulumi.StringInput) PrivateApplicationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) PrivateApplication {
		return vs[0].(map[string]PrivateApplication)[vs[1].(string)]
	}).(PrivateApplicationOutput)
}

func init() {
	pulumi.RegisterOutputType(PrivateApplicationOutput{})
	pulumi.RegisterOutputType(PrivateApplicationPtrOutput{})
	pulumi.RegisterOutputType(PrivateApplicationArrayOutput{})
	pulumi.RegisterOutputType(PrivateApplicationMapOutput{})
}