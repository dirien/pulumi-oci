// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Image resource in Oracle Cloud Infrastructure Core service.
//
// Creates a boot disk image for the specified instance or imports an exported image from the Oracle Cloud Infrastructure Object Storage service.
//
// When creating a new image, you must provide the OCID of the instance you want to use as the basis for the image, and
// the OCID of the compartment containing that instance. For more information about images,
// see [Managing Custom Images](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/managingcustomimages.htm).
//
// When importing an exported image from Object Storage, you specify the source information
// in [ImageSourceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/ImageSourceDetails).
//
// When importing an image based on the namespace, bucket name, and object name,
// use [ImageSourceViaObjectStorageTupleDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/ImageSourceViaObjectStorageTupleDetails).
//
// When importing an image based on the Object Storage URL, use
// [ImageSourceViaObjectStorageUriDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/ImageSourceViaObjectStorageUriDetails).
// See [Object Storage URLs](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/imageimportexport.htm#URLs) and [Using Pre-Authenticated Requests](https://docs.cloud.oracle.com/iaas/Content/Object/Tasks/usingpreauthenticatedrequests.htm)
// for constructing URLs for image import/export.
//
// For more information about importing exported images, see
// [Image Import/Export](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/imageimportexport.htm).
//
// You may optionally specify a *display name* for the image, which is simply a friendly name or description.
// It does not have to be unique, and you can change it. See [UpdateImage](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Image/UpdateImage).
// Avoid entering confidential information.
//
// ## Example Usage
// ### Create image from instance in tenancy
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
// 		_, err := core.NewImage(ctx, "testImage", &core.ImageArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			InstanceId:    pulumi.Any(oci_core_instance.Test_instance.Id),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			DisplayName: pulumi.Any(_var.Image_display_name),
// 			LaunchMode:  pulumi.Any(_var.Image_launch_mode),
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
// ### Create image from exported image via direct access to object store
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
// 		_, err := core.NewImage(ctx, "testImage", &core.ImageArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			DisplayName:   pulumi.Any(_var.Image_display_name),
// 			LaunchMode:    pulumi.Any(_var.Image_launch_mode),
// 			ImageSourceDetails: &core.ImageImageSourceDetailsArgs{
// 				SourceType:             pulumi.String("objectStorageTuple"),
// 				BucketName:             pulumi.Any(_var.Bucket_name),
// 				NamespaceName:          pulumi.Any(_var.Namespace),
// 				ObjectName:             pulumi.Any(_var.Object_name),
// 				OperatingSystem:        pulumi.Any(_var.Image_image_source_details_operating_system),
// 				OperatingSystemVersion: pulumi.Any(_var.Image_image_source_details_operating_system_version),
// 				SourceImageType:        pulumi.Any(_var.Source_image_type),
// 			},
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
// ### Create image from exported image at publicly accessible uri
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
// 		_, err := core.NewImage(ctx, "testImage", &core.ImageArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			DisplayName:   pulumi.Any(_var.Image_display_name),
// 			LaunchMode:    pulumi.Any(_var.Image_launch_mode),
// 			ImageSourceDetails: &core.ImageImageSourceDetailsArgs{
// 				SourceType:             pulumi.String("objectStorageUri"),
// 				SourceUri:              pulumi.Any(_var.Source_uri),
// 				OperatingSystem:        pulumi.Any(_var.Image_image_source_details_operating_system),
// 				OperatingSystemVersion: pulumi.Any(_var.Image_image_source_details_operating_system_version),
// 				SourceImageType:        pulumi.Any(_var.Source_image_type),
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
// Images can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:core/image:Image test_image "id"
// ```
type Image struct {
	pulumi.CustomResourceState

	// Oracle Cloud Agent features supported on the image.
	AgentFeatures ImageAgentFeaturesOutput `pulumi:"agentFeatures"`
	// The OCID of the image originally used to launch the instance.
	BaseImageId pulumi.StringOutput `pulumi:"baseImageId"`
	// The size of the internal storage for this image that is subject to billing (1 GB = 1,073,741,824 bytes).  Example: `100`
	BillableSizeInGbs pulumi.StringOutput `pulumi:"billableSizeInGbs"`
	// (Updatable) The OCID of the compartment you want the image to be created in.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Whether instances launched with this image can be used to create new images. For example, you cannot create an image of an Oracle Database instance.  Example: `true`
	CreateImageAllowed pulumi.BoolOutput `pulumi:"createImageAllowed"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the image. It does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags       pulumi.MapOutput                 `pulumi:"freeformTags"`
	ImageSourceDetails ImageImageSourceDetailsPtrOutput `pulumi:"imageSourceDetails"`
	// The OCID of the instance you want to use as the basis for the image.
	InstanceId pulumi.StringPtrOutput `pulumi:"instanceId"`
	// Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
	LaunchMode pulumi.StringOutput `pulumi:"launchMode"`
	// Options for tuning the compatibility and performance of VM shapes. The values that you specify override any default values.
	LaunchOptions ImageLaunchOptionsOutput `pulumi:"launchOptions"`
	// The listing type of the image. The default value is "NONE".
	ListingType pulumi.StringOutput `pulumi:"listingType"`
	// The image's operating system.  Example: `Oracle Linux`
	OperatingSystem pulumi.StringOutput `pulumi:"operatingSystem"`
	// The image's operating system version.  Example: `7.2`
	OperatingSystemVersion pulumi.StringOutput `pulumi:"operatingSystemVersion"`
	// The boot volume size for an instance launched from this image (1 MB = 1,048,576 bytes). Note this is not the same as the size of the image when it was exported or the actual size of the image.  Example: `47694`
	SizeInMbs pulumi.StringOutput `pulumi:"sizeInMbs"`
	// The current state of the image.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the image was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewImage registers a new resource with the given unique name, arguments, and options.
func NewImage(ctx *pulumi.Context,
	name string, args *ImageArgs, opts ...pulumi.ResourceOption) (*Image, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	var resource Image
	err := ctx.RegisterResource("oci:core/image:Image", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetImage gets an existing Image resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetImage(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ImageState, opts ...pulumi.ResourceOption) (*Image, error) {
	var resource Image
	err := ctx.ReadResource("oci:core/image:Image", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Image resources.
type imageState struct {
	// Oracle Cloud Agent features supported on the image.
	AgentFeatures *ImageAgentFeatures `pulumi:"agentFeatures"`
	// The OCID of the image originally used to launch the instance.
	BaseImageId *string `pulumi:"baseImageId"`
	// The size of the internal storage for this image that is subject to billing (1 GB = 1,073,741,824 bytes).  Example: `100`
	BillableSizeInGbs *string `pulumi:"billableSizeInGbs"`
	// (Updatable) The OCID of the compartment you want the image to be created in.
	CompartmentId *string `pulumi:"compartmentId"`
	// Whether instances launched with this image can be used to create new images. For example, you cannot create an image of an Oracle Database instance.  Example: `true`
	CreateImageAllowed *bool `pulumi:"createImageAllowed"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the image. It does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags       map[string]interface{}   `pulumi:"freeformTags"`
	ImageSourceDetails *ImageImageSourceDetails `pulumi:"imageSourceDetails"`
	// The OCID of the instance you want to use as the basis for the image.
	InstanceId *string `pulumi:"instanceId"`
	// Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
	LaunchMode *string `pulumi:"launchMode"`
	// Options for tuning the compatibility and performance of VM shapes. The values that you specify override any default values.
	LaunchOptions *ImageLaunchOptions `pulumi:"launchOptions"`
	// The listing type of the image. The default value is "NONE".
	ListingType *string `pulumi:"listingType"`
	// The image's operating system.  Example: `Oracle Linux`
	OperatingSystem *string `pulumi:"operatingSystem"`
	// The image's operating system version.  Example: `7.2`
	OperatingSystemVersion *string `pulumi:"operatingSystemVersion"`
	// The boot volume size for an instance launched from this image (1 MB = 1,048,576 bytes). Note this is not the same as the size of the image when it was exported or the actual size of the image.  Example: `47694`
	SizeInMbs *string `pulumi:"sizeInMbs"`
	// The current state of the image.
	State *string `pulumi:"state"`
	// The date and time the image was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type ImageState struct {
	// Oracle Cloud Agent features supported on the image.
	AgentFeatures ImageAgentFeaturesPtrInput
	// The OCID of the image originally used to launch the instance.
	BaseImageId pulumi.StringPtrInput
	// The size of the internal storage for this image that is subject to billing (1 GB = 1,073,741,824 bytes).  Example: `100`
	BillableSizeInGbs pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment you want the image to be created in.
	CompartmentId pulumi.StringPtrInput
	// Whether instances launched with this image can be used to create new images. For example, you cannot create an image of an Oracle Database instance.  Example: `true`
	CreateImageAllowed pulumi.BoolPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name for the image. It does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags       pulumi.MapInput
	ImageSourceDetails ImageImageSourceDetailsPtrInput
	// The OCID of the instance you want to use as the basis for the image.
	InstanceId pulumi.StringPtrInput
	// Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
	LaunchMode pulumi.StringPtrInput
	// Options for tuning the compatibility and performance of VM shapes. The values that you specify override any default values.
	LaunchOptions ImageLaunchOptionsPtrInput
	// The listing type of the image. The default value is "NONE".
	ListingType pulumi.StringPtrInput
	// The image's operating system.  Example: `Oracle Linux`
	OperatingSystem pulumi.StringPtrInput
	// The image's operating system version.  Example: `7.2`
	OperatingSystemVersion pulumi.StringPtrInput
	// The boot volume size for an instance launched from this image (1 MB = 1,048,576 bytes). Note this is not the same as the size of the image when it was exported or the actual size of the image.  Example: `47694`
	SizeInMbs pulumi.StringPtrInput
	// The current state of the image.
	State pulumi.StringPtrInput
	// The date and time the image was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (ImageState) ElementType() reflect.Type {
	return reflect.TypeOf((*imageState)(nil)).Elem()
}

type imageArgs struct {
	// (Updatable) The OCID of the compartment you want the image to be created in.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the image. It does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags       map[string]interface{}   `pulumi:"freeformTags"`
	ImageSourceDetails *ImageImageSourceDetails `pulumi:"imageSourceDetails"`
	// The OCID of the instance you want to use as the basis for the image.
	InstanceId *string `pulumi:"instanceId"`
	// Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
	LaunchMode *string `pulumi:"launchMode"`
}

// The set of arguments for constructing a Image resource.
type ImageArgs struct {
	// (Updatable) The OCID of the compartment you want the image to be created in.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name for the image. It does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags       pulumi.MapInput
	ImageSourceDetails ImageImageSourceDetailsPtrInput
	// The OCID of the instance you want to use as the basis for the image.
	InstanceId pulumi.StringPtrInput
	// Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
	LaunchMode pulumi.StringPtrInput
}

func (ImageArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*imageArgs)(nil)).Elem()
}

type ImageInput interface {
	pulumi.Input

	ToImageOutput() ImageOutput
	ToImageOutputWithContext(ctx context.Context) ImageOutput
}

func (*Image) ElementType() reflect.Type {
	return reflect.TypeOf((*Image)(nil))
}

func (i *Image) ToImageOutput() ImageOutput {
	return i.ToImageOutputWithContext(context.Background())
}

func (i *Image) ToImageOutputWithContext(ctx context.Context) ImageOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ImageOutput)
}

func (i *Image) ToImagePtrOutput() ImagePtrOutput {
	return i.ToImagePtrOutputWithContext(context.Background())
}

func (i *Image) ToImagePtrOutputWithContext(ctx context.Context) ImagePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ImagePtrOutput)
}

type ImagePtrInput interface {
	pulumi.Input

	ToImagePtrOutput() ImagePtrOutput
	ToImagePtrOutputWithContext(ctx context.Context) ImagePtrOutput
}

type imagePtrType ImageArgs

func (*imagePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**Image)(nil))
}

func (i *imagePtrType) ToImagePtrOutput() ImagePtrOutput {
	return i.ToImagePtrOutputWithContext(context.Background())
}

func (i *imagePtrType) ToImagePtrOutputWithContext(ctx context.Context) ImagePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ImagePtrOutput)
}

// ImageArrayInput is an input type that accepts ImageArray and ImageArrayOutput values.
// You can construct a concrete instance of `ImageArrayInput` via:
//
//          ImageArray{ ImageArgs{...} }
type ImageArrayInput interface {
	pulumi.Input

	ToImageArrayOutput() ImageArrayOutput
	ToImageArrayOutputWithContext(context.Context) ImageArrayOutput
}

type ImageArray []ImageInput

func (ImageArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Image)(nil)).Elem()
}

func (i ImageArray) ToImageArrayOutput() ImageArrayOutput {
	return i.ToImageArrayOutputWithContext(context.Background())
}

func (i ImageArray) ToImageArrayOutputWithContext(ctx context.Context) ImageArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ImageArrayOutput)
}

// ImageMapInput is an input type that accepts ImageMap and ImageMapOutput values.
// You can construct a concrete instance of `ImageMapInput` via:
//
//          ImageMap{ "key": ImageArgs{...} }
type ImageMapInput interface {
	pulumi.Input

	ToImageMapOutput() ImageMapOutput
	ToImageMapOutputWithContext(context.Context) ImageMapOutput
}

type ImageMap map[string]ImageInput

func (ImageMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Image)(nil)).Elem()
}

func (i ImageMap) ToImageMapOutput() ImageMapOutput {
	return i.ToImageMapOutputWithContext(context.Background())
}

func (i ImageMap) ToImageMapOutputWithContext(ctx context.Context) ImageMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ImageMapOutput)
}

type ImageOutput struct {
	*pulumi.OutputState
}

func (ImageOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*Image)(nil))
}

func (o ImageOutput) ToImageOutput() ImageOutput {
	return o
}

func (o ImageOutput) ToImageOutputWithContext(ctx context.Context) ImageOutput {
	return o
}

func (o ImageOutput) ToImagePtrOutput() ImagePtrOutput {
	return o.ToImagePtrOutputWithContext(context.Background())
}

func (o ImageOutput) ToImagePtrOutputWithContext(ctx context.Context) ImagePtrOutput {
	return o.ApplyT(func(v Image) *Image {
		return &v
	}).(ImagePtrOutput)
}

type ImagePtrOutput struct {
	*pulumi.OutputState
}

func (ImagePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Image)(nil))
}

func (o ImagePtrOutput) ToImagePtrOutput() ImagePtrOutput {
	return o
}

func (o ImagePtrOutput) ToImagePtrOutputWithContext(ctx context.Context) ImagePtrOutput {
	return o
}

type ImageArrayOutput struct{ *pulumi.OutputState }

func (ImageArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]Image)(nil))
}

func (o ImageArrayOutput) ToImageArrayOutput() ImageArrayOutput {
	return o
}

func (o ImageArrayOutput) ToImageArrayOutputWithContext(ctx context.Context) ImageArrayOutput {
	return o
}

func (o ImageArrayOutput) Index(i pulumi.IntInput) ImageOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) Image {
		return vs[0].([]Image)[vs[1].(int)]
	}).(ImageOutput)
}

type ImageMapOutput struct{ *pulumi.OutputState }

func (ImageMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]Image)(nil))
}

func (o ImageMapOutput) ToImageMapOutput() ImageMapOutput {
	return o
}

func (o ImageMapOutput) ToImageMapOutputWithContext(ctx context.Context) ImageMapOutput {
	return o
}

func (o ImageMapOutput) MapIndex(k pulumi.StringInput) ImageOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) Image {
		return vs[0].(map[string]Image)[vs[1].(string)]
	}).(ImageOutput)
}

func init() {
	pulumi.RegisterOutputType(ImageOutput{})
	pulumi.RegisterOutputType(ImagePtrOutput{})
	pulumi.RegisterOutputType(ImageArrayOutput{})
	pulumi.RegisterOutputType(ImageMapOutput{})
}
