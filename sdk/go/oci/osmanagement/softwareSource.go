// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagement

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Software Source resource in Oracle Cloud Infrastructure OS Management service.
//
// Creates a new custom Software Source on the management system.
// This will not contain any packages after it is first created,
// and they must be added later.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/osmanagement"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := osmanagement.NewSoftwareSource(ctx, "testSoftwareSource", &osmanagement.SoftwareSourceArgs{
// 			ArchType:      pulumi.Any(_var.Software_source_arch_type),
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			DisplayName:   pulumi.Any(_var.Software_source_display_name),
// 			ChecksumType:  pulumi.Any(_var.Software_source_checksum_type),
// 			DefinedTags: pulumi.AnyMap{
// 				"foo-namespace.bar-key": pulumi.Any("value"),
// 			},
// 			Description: pulumi.Any(_var.Software_source_description),
// 			FreeformTags: pulumi.AnyMap{
// 				"bar-key": pulumi.Any("value"),
// 			},
// 			MaintainerEmail: pulumi.Any(_var.Software_source_maintainer_email),
// 			MaintainerName:  pulumi.Any(_var.Software_source_maintainer_name),
// 			MaintainerPhone: pulumi.Any(_var.Software_source_maintainer_phone),
// 			ParentId:        pulumi.Any(oci_osmanagement_parent.Test_parent.Id),
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
// SoftwareSources can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:osmanagement/softwareSource:SoftwareSource test_software_source "id"
// ```
type SoftwareSource struct {
	pulumi.CustomResourceState

	// The architecture type supported by the Software Source
	ArchType pulumi.StringOutput `pulumi:"archType"`
	// list of the Managed Instances associated with this Software Sources
	AssociatedManagedInstances SoftwareSourceAssociatedManagedInstanceArrayOutput `pulumi:"associatedManagedInstances"`
	// (Updatable) The yum repository checksum type used by this software source
	ChecksumType pulumi.StringOutput `pulumi:"checksumType"`
	// (Updatable) OCID for the Compartment
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Information specified by the user about the software source
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) User friendly name for the software source
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// Fingerprint of the GPG key for this software source
	GpgKeyFingerprint pulumi.StringOutput `pulumi:"gpgKeyFingerprint"`
	// ID of the GPG key for this software source
	GpgKeyId pulumi.StringOutput `pulumi:"gpgKeyId"`
	// URL of the GPG key for this software source
	GpgKeyUrl pulumi.StringOutput `pulumi:"gpgKeyUrl"`
	// (Updatable) Email address of the person maintaining this software source
	MaintainerEmail pulumi.StringOutput `pulumi:"maintainerEmail"`
	// (Updatable) Name of the person maintaining this software source
	MaintainerName pulumi.StringOutput `pulumi:"maintainerName"`
	// (Updatable) Phone number of the person maintaining this software source
	MaintainerPhone pulumi.StringOutput `pulumi:"maintainerPhone"`
	// Number of packages
	Packages pulumi.IntOutput `pulumi:"packages"`
	// OCID for the parent software source, if there is one
	ParentId pulumi.StringOutput `pulumi:"parentId"`
	// Display name the parent software source, if there is one
	ParentName pulumi.StringOutput `pulumi:"parentName"`
	// Type of the Software Source
	RepoType pulumi.StringOutput `pulumi:"repoType"`
	// The current state of the Software Source.
	State pulumi.StringOutput `pulumi:"state"`
	// status of the software source.
	Status pulumi.StringOutput `pulumi:"status"`
	// URL for the repostiory
	Url pulumi.StringOutput `pulumi:"url"`
}

// NewSoftwareSource registers a new resource with the given unique name, arguments, and options.
func NewSoftwareSource(ctx *pulumi.Context,
	name string, args *SoftwareSourceArgs, opts ...pulumi.ResourceOption) (*SoftwareSource, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ArchType == nil {
		return nil, errors.New("invalid value for required argument 'ArchType'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	var resource SoftwareSource
	err := ctx.RegisterResource("oci:osmanagement/softwareSource:SoftwareSource", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSoftwareSource gets an existing SoftwareSource resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSoftwareSource(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SoftwareSourceState, opts ...pulumi.ResourceOption) (*SoftwareSource, error) {
	var resource SoftwareSource
	err := ctx.ReadResource("oci:osmanagement/softwareSource:SoftwareSource", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering SoftwareSource resources.
type softwareSourceState struct {
	// The architecture type supported by the Software Source
	ArchType *string `pulumi:"archType"`
	// list of the Managed Instances associated with this Software Sources
	AssociatedManagedInstances []SoftwareSourceAssociatedManagedInstance `pulumi:"associatedManagedInstances"`
	// (Updatable) The yum repository checksum type used by this software source
	ChecksumType *string `pulumi:"checksumType"`
	// (Updatable) OCID for the Compartment
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Information specified by the user about the software source
	Description *string `pulumi:"description"`
	// (Updatable) User friendly name for the software source
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Fingerprint of the GPG key for this software source
	GpgKeyFingerprint *string `pulumi:"gpgKeyFingerprint"`
	// ID of the GPG key for this software source
	GpgKeyId *string `pulumi:"gpgKeyId"`
	// URL of the GPG key for this software source
	GpgKeyUrl *string `pulumi:"gpgKeyUrl"`
	// (Updatable) Email address of the person maintaining this software source
	MaintainerEmail *string `pulumi:"maintainerEmail"`
	// (Updatable) Name of the person maintaining this software source
	MaintainerName *string `pulumi:"maintainerName"`
	// (Updatable) Phone number of the person maintaining this software source
	MaintainerPhone *string `pulumi:"maintainerPhone"`
	// Number of packages
	Packages *int `pulumi:"packages"`
	// OCID for the parent software source, if there is one
	ParentId *string `pulumi:"parentId"`
	// Display name the parent software source, if there is one
	ParentName *string `pulumi:"parentName"`
	// Type of the Software Source
	RepoType *string `pulumi:"repoType"`
	// The current state of the Software Source.
	State *string `pulumi:"state"`
	// status of the software source.
	Status *string `pulumi:"status"`
	// URL for the repostiory
	Url *string `pulumi:"url"`
}

type SoftwareSourceState struct {
	// The architecture type supported by the Software Source
	ArchType pulumi.StringPtrInput
	// list of the Managed Instances associated with this Software Sources
	AssociatedManagedInstances SoftwareSourceAssociatedManagedInstanceArrayInput
	// (Updatable) The yum repository checksum type used by this software source
	ChecksumType pulumi.StringPtrInput
	// (Updatable) OCID for the Compartment
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Information specified by the user about the software source
	Description pulumi.StringPtrInput
	// (Updatable) User friendly name for the software source
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// Fingerprint of the GPG key for this software source
	GpgKeyFingerprint pulumi.StringPtrInput
	// ID of the GPG key for this software source
	GpgKeyId pulumi.StringPtrInput
	// URL of the GPG key for this software source
	GpgKeyUrl pulumi.StringPtrInput
	// (Updatable) Email address of the person maintaining this software source
	MaintainerEmail pulumi.StringPtrInput
	// (Updatable) Name of the person maintaining this software source
	MaintainerName pulumi.StringPtrInput
	// (Updatable) Phone number of the person maintaining this software source
	MaintainerPhone pulumi.StringPtrInput
	// Number of packages
	Packages pulumi.IntPtrInput
	// OCID for the parent software source, if there is one
	ParentId pulumi.StringPtrInput
	// Display name the parent software source, if there is one
	ParentName pulumi.StringPtrInput
	// Type of the Software Source
	RepoType pulumi.StringPtrInput
	// The current state of the Software Source.
	State pulumi.StringPtrInput
	// status of the software source.
	Status pulumi.StringPtrInput
	// URL for the repostiory
	Url pulumi.StringPtrInput
}

func (SoftwareSourceState) ElementType() reflect.Type {
	return reflect.TypeOf((*softwareSourceState)(nil)).Elem()
}

type softwareSourceArgs struct {
	// The architecture type supported by the Software Source
	ArchType string `pulumi:"archType"`
	// (Updatable) The yum repository checksum type used by this software source
	ChecksumType *string `pulumi:"checksumType"`
	// (Updatable) OCID for the Compartment
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Information specified by the user about the software source
	Description *string `pulumi:"description"`
	// (Updatable) User friendly name for the software source
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Email address of the person maintaining this software source
	MaintainerEmail *string `pulumi:"maintainerEmail"`
	// (Updatable) Name of the person maintaining this software source
	MaintainerName *string `pulumi:"maintainerName"`
	// (Updatable) Phone number of the person maintaining this software source
	MaintainerPhone *string `pulumi:"maintainerPhone"`
	// OCID for the parent software source, if there is one
	ParentId *string `pulumi:"parentId"`
}

// The set of arguments for constructing a SoftwareSource resource.
type SoftwareSourceArgs struct {
	// The architecture type supported by the Software Source
	ArchType pulumi.StringInput
	// (Updatable) The yum repository checksum type used by this software source
	ChecksumType pulumi.StringPtrInput
	// (Updatable) OCID for the Compartment
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Information specified by the user about the software source
	Description pulumi.StringPtrInput
	// (Updatable) User friendly name for the software source
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Email address of the person maintaining this software source
	MaintainerEmail pulumi.StringPtrInput
	// (Updatable) Name of the person maintaining this software source
	MaintainerName pulumi.StringPtrInput
	// (Updatable) Phone number of the person maintaining this software source
	MaintainerPhone pulumi.StringPtrInput
	// OCID for the parent software source, if there is one
	ParentId pulumi.StringPtrInput
}

func (SoftwareSourceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*softwareSourceArgs)(nil)).Elem()
}

type SoftwareSourceInput interface {
	pulumi.Input

	ToSoftwareSourceOutput() SoftwareSourceOutput
	ToSoftwareSourceOutputWithContext(ctx context.Context) SoftwareSourceOutput
}

func (*SoftwareSource) ElementType() reflect.Type {
	return reflect.TypeOf((*SoftwareSource)(nil))
}

func (i *SoftwareSource) ToSoftwareSourceOutput() SoftwareSourceOutput {
	return i.ToSoftwareSourceOutputWithContext(context.Background())
}

func (i *SoftwareSource) ToSoftwareSourceOutputWithContext(ctx context.Context) SoftwareSourceOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SoftwareSourceOutput)
}

func (i *SoftwareSource) ToSoftwareSourcePtrOutput() SoftwareSourcePtrOutput {
	return i.ToSoftwareSourcePtrOutputWithContext(context.Background())
}

func (i *SoftwareSource) ToSoftwareSourcePtrOutputWithContext(ctx context.Context) SoftwareSourcePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SoftwareSourcePtrOutput)
}

type SoftwareSourcePtrInput interface {
	pulumi.Input

	ToSoftwareSourcePtrOutput() SoftwareSourcePtrOutput
	ToSoftwareSourcePtrOutputWithContext(ctx context.Context) SoftwareSourcePtrOutput
}

type softwareSourcePtrType SoftwareSourceArgs

func (*softwareSourcePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**SoftwareSource)(nil))
}

func (i *softwareSourcePtrType) ToSoftwareSourcePtrOutput() SoftwareSourcePtrOutput {
	return i.ToSoftwareSourcePtrOutputWithContext(context.Background())
}

func (i *softwareSourcePtrType) ToSoftwareSourcePtrOutputWithContext(ctx context.Context) SoftwareSourcePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SoftwareSourcePtrOutput)
}

// SoftwareSourceArrayInput is an input type that accepts SoftwareSourceArray and SoftwareSourceArrayOutput values.
// You can construct a concrete instance of `SoftwareSourceArrayInput` via:
//
//          SoftwareSourceArray{ SoftwareSourceArgs{...} }
type SoftwareSourceArrayInput interface {
	pulumi.Input

	ToSoftwareSourceArrayOutput() SoftwareSourceArrayOutput
	ToSoftwareSourceArrayOutputWithContext(context.Context) SoftwareSourceArrayOutput
}

type SoftwareSourceArray []SoftwareSourceInput

func (SoftwareSourceArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SoftwareSource)(nil)).Elem()
}

func (i SoftwareSourceArray) ToSoftwareSourceArrayOutput() SoftwareSourceArrayOutput {
	return i.ToSoftwareSourceArrayOutputWithContext(context.Background())
}

func (i SoftwareSourceArray) ToSoftwareSourceArrayOutputWithContext(ctx context.Context) SoftwareSourceArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SoftwareSourceArrayOutput)
}

// SoftwareSourceMapInput is an input type that accepts SoftwareSourceMap and SoftwareSourceMapOutput values.
// You can construct a concrete instance of `SoftwareSourceMapInput` via:
//
//          SoftwareSourceMap{ "key": SoftwareSourceArgs{...} }
type SoftwareSourceMapInput interface {
	pulumi.Input

	ToSoftwareSourceMapOutput() SoftwareSourceMapOutput
	ToSoftwareSourceMapOutputWithContext(context.Context) SoftwareSourceMapOutput
}

type SoftwareSourceMap map[string]SoftwareSourceInput

func (SoftwareSourceMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SoftwareSource)(nil)).Elem()
}

func (i SoftwareSourceMap) ToSoftwareSourceMapOutput() SoftwareSourceMapOutput {
	return i.ToSoftwareSourceMapOutputWithContext(context.Background())
}

func (i SoftwareSourceMap) ToSoftwareSourceMapOutputWithContext(ctx context.Context) SoftwareSourceMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SoftwareSourceMapOutput)
}

type SoftwareSourceOutput struct {
	*pulumi.OutputState
}

func (SoftwareSourceOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*SoftwareSource)(nil))
}

func (o SoftwareSourceOutput) ToSoftwareSourceOutput() SoftwareSourceOutput {
	return o
}

func (o SoftwareSourceOutput) ToSoftwareSourceOutputWithContext(ctx context.Context) SoftwareSourceOutput {
	return o
}

func (o SoftwareSourceOutput) ToSoftwareSourcePtrOutput() SoftwareSourcePtrOutput {
	return o.ToSoftwareSourcePtrOutputWithContext(context.Background())
}

func (o SoftwareSourceOutput) ToSoftwareSourcePtrOutputWithContext(ctx context.Context) SoftwareSourcePtrOutput {
	return o.ApplyT(func(v SoftwareSource) *SoftwareSource {
		return &v
	}).(SoftwareSourcePtrOutput)
}

type SoftwareSourcePtrOutput struct {
	*pulumi.OutputState
}

func (SoftwareSourcePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**SoftwareSource)(nil))
}

func (o SoftwareSourcePtrOutput) ToSoftwareSourcePtrOutput() SoftwareSourcePtrOutput {
	return o
}

func (o SoftwareSourcePtrOutput) ToSoftwareSourcePtrOutputWithContext(ctx context.Context) SoftwareSourcePtrOutput {
	return o
}

type SoftwareSourceArrayOutput struct{ *pulumi.OutputState }

func (SoftwareSourceArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]SoftwareSource)(nil))
}

func (o SoftwareSourceArrayOutput) ToSoftwareSourceArrayOutput() SoftwareSourceArrayOutput {
	return o
}

func (o SoftwareSourceArrayOutput) ToSoftwareSourceArrayOutputWithContext(ctx context.Context) SoftwareSourceArrayOutput {
	return o
}

func (o SoftwareSourceArrayOutput) Index(i pulumi.IntInput) SoftwareSourceOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) SoftwareSource {
		return vs[0].([]SoftwareSource)[vs[1].(int)]
	}).(SoftwareSourceOutput)
}

type SoftwareSourceMapOutput struct{ *pulumi.OutputState }

func (SoftwareSourceMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]SoftwareSource)(nil))
}

func (o SoftwareSourceMapOutput) ToSoftwareSourceMapOutput() SoftwareSourceMapOutput {
	return o
}

func (o SoftwareSourceMapOutput) ToSoftwareSourceMapOutputWithContext(ctx context.Context) SoftwareSourceMapOutput {
	return o
}

func (o SoftwareSourceMapOutput) MapIndex(k pulumi.StringInput) SoftwareSourceOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) SoftwareSource {
		return vs[0].(map[string]SoftwareSource)[vs[1].(string)]
	}).(SoftwareSourceOutput)
}

func init() {
	pulumi.RegisterOutputType(SoftwareSourceOutput{})
	pulumi.RegisterOutputType(SoftwareSourcePtrOutput{})
	pulumi.RegisterOutputType(SoftwareSourceArrayOutput{})
	pulumi.RegisterOutputType(SoftwareSourceMapOutput{})
}
