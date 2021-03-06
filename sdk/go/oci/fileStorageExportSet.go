// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// ## Import
//
// ExportSets can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/fileStorageExportSet:FileStorageExportSet test_export_set "id"
// ```
type FileStorageExportSet struct {
	pulumi.CustomResourceState

	// The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringOutput `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
	MaxFsStatBytes pulumi.StringOutput `pulumi:"maxFsStatBytes"`
	// (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'.
	MaxFsStatFiles pulumi.StringOutput `pulumi:"maxFsStatFiles"`
	// (Updatable) The OCID of the mount target that the export set is associated with
	MountTargetId pulumi.StringOutput `pulumi:"mountTargetId"`
	// The current state of the export set.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
	VcnId pulumi.StringOutput `pulumi:"vcnId"`
}

// NewFileStorageExportSet registers a new resource with the given unique name, arguments, and options.
func NewFileStorageExportSet(ctx *pulumi.Context,
	name string, args *FileStorageExportSetArgs, opts ...pulumi.ResourceOption) (*FileStorageExportSet, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.MountTargetId == nil {
		return nil, errors.New("invalid value for required argument 'MountTargetId'")
	}
	var resource FileStorageExportSet
	err := ctx.RegisterResource("oci:index/fileStorageExportSet:FileStorageExportSet", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetFileStorageExportSet gets an existing FileStorageExportSet resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetFileStorageExportSet(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *FileStorageExportSetState, opts ...pulumi.ResourceOption) (*FileStorageExportSet, error) {
	var resource FileStorageExportSet
	err := ctx.ReadResource("oci:index/fileStorageExportSet:FileStorageExportSet", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering FileStorageExportSet resources.
type fileStorageExportSetState struct {
	// The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
	MaxFsStatBytes *string `pulumi:"maxFsStatBytes"`
	// (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'.
	MaxFsStatFiles *string `pulumi:"maxFsStatFiles"`
	// (Updatable) The OCID of the mount target that the export set is associated with
	MountTargetId *string `pulumi:"mountTargetId"`
	// The current state of the export set.
	State *string `pulumi:"state"`
	// The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
	VcnId *string `pulumi:"vcnId"`
}

type FileStorageExportSetState struct {
	// The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
	DisplayName pulumi.StringPtrInput
	// (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
	MaxFsStatBytes pulumi.StringPtrInput
	// (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'.
	MaxFsStatFiles pulumi.StringPtrInput
	// (Updatable) The OCID of the mount target that the export set is associated with
	MountTargetId pulumi.StringPtrInput
	// The current state of the export set.
	State pulumi.StringPtrInput
	// The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
	VcnId pulumi.StringPtrInput
}

func (FileStorageExportSetState) ElementType() reflect.Type {
	return reflect.TypeOf((*fileStorageExportSetState)(nil)).Elem()
}

type fileStorageExportSetArgs struct {
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
	MaxFsStatBytes *string `pulumi:"maxFsStatBytes"`
	// (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'.
	MaxFsStatFiles *string `pulumi:"maxFsStatFiles"`
	// (Updatable) The OCID of the mount target that the export set is associated with
	MountTargetId string `pulumi:"mountTargetId"`
}

// The set of arguments for constructing a FileStorageExportSet resource.
type FileStorageExportSetArgs struct {
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
	DisplayName pulumi.StringPtrInput
	// (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
	MaxFsStatBytes pulumi.StringPtrInput
	// (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'.
	MaxFsStatFiles pulumi.StringPtrInput
	// (Updatable) The OCID of the mount target that the export set is associated with
	MountTargetId pulumi.StringInput
}

func (FileStorageExportSetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*fileStorageExportSetArgs)(nil)).Elem()
}

type FileStorageExportSetInput interface {
	pulumi.Input

	ToFileStorageExportSetOutput() FileStorageExportSetOutput
	ToFileStorageExportSetOutputWithContext(ctx context.Context) FileStorageExportSetOutput
}

func (*FileStorageExportSet) ElementType() reflect.Type {
	return reflect.TypeOf((*FileStorageExportSet)(nil))
}

func (i *FileStorageExportSet) ToFileStorageExportSetOutput() FileStorageExportSetOutput {
	return i.ToFileStorageExportSetOutputWithContext(context.Background())
}

func (i *FileStorageExportSet) ToFileStorageExportSetOutputWithContext(ctx context.Context) FileStorageExportSetOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileStorageExportSetOutput)
}

func (i *FileStorageExportSet) ToFileStorageExportSetPtrOutput() FileStorageExportSetPtrOutput {
	return i.ToFileStorageExportSetPtrOutputWithContext(context.Background())
}

func (i *FileStorageExportSet) ToFileStorageExportSetPtrOutputWithContext(ctx context.Context) FileStorageExportSetPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileStorageExportSetPtrOutput)
}

type FileStorageExportSetPtrInput interface {
	pulumi.Input

	ToFileStorageExportSetPtrOutput() FileStorageExportSetPtrOutput
	ToFileStorageExportSetPtrOutputWithContext(ctx context.Context) FileStorageExportSetPtrOutput
}

type fileStorageExportSetPtrType FileStorageExportSetArgs

func (*fileStorageExportSetPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**FileStorageExportSet)(nil))
}

func (i *fileStorageExportSetPtrType) ToFileStorageExportSetPtrOutput() FileStorageExportSetPtrOutput {
	return i.ToFileStorageExportSetPtrOutputWithContext(context.Background())
}

func (i *fileStorageExportSetPtrType) ToFileStorageExportSetPtrOutputWithContext(ctx context.Context) FileStorageExportSetPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileStorageExportSetPtrOutput)
}

// FileStorageExportSetArrayInput is an input type that accepts FileStorageExportSetArray and FileStorageExportSetArrayOutput values.
// You can construct a concrete instance of `FileStorageExportSetArrayInput` via:
//
//          FileStorageExportSetArray{ FileStorageExportSetArgs{...} }
type FileStorageExportSetArrayInput interface {
	pulumi.Input

	ToFileStorageExportSetArrayOutput() FileStorageExportSetArrayOutput
	ToFileStorageExportSetArrayOutputWithContext(context.Context) FileStorageExportSetArrayOutput
}

type FileStorageExportSetArray []FileStorageExportSetInput

func (FileStorageExportSetArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*FileStorageExportSet)(nil)).Elem()
}

func (i FileStorageExportSetArray) ToFileStorageExportSetArrayOutput() FileStorageExportSetArrayOutput {
	return i.ToFileStorageExportSetArrayOutputWithContext(context.Background())
}

func (i FileStorageExportSetArray) ToFileStorageExportSetArrayOutputWithContext(ctx context.Context) FileStorageExportSetArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileStorageExportSetArrayOutput)
}

// FileStorageExportSetMapInput is an input type that accepts FileStorageExportSetMap and FileStorageExportSetMapOutput values.
// You can construct a concrete instance of `FileStorageExportSetMapInput` via:
//
//          FileStorageExportSetMap{ "key": FileStorageExportSetArgs{...} }
type FileStorageExportSetMapInput interface {
	pulumi.Input

	ToFileStorageExportSetMapOutput() FileStorageExportSetMapOutput
	ToFileStorageExportSetMapOutputWithContext(context.Context) FileStorageExportSetMapOutput
}

type FileStorageExportSetMap map[string]FileStorageExportSetInput

func (FileStorageExportSetMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*FileStorageExportSet)(nil)).Elem()
}

func (i FileStorageExportSetMap) ToFileStorageExportSetMapOutput() FileStorageExportSetMapOutput {
	return i.ToFileStorageExportSetMapOutputWithContext(context.Background())
}

func (i FileStorageExportSetMap) ToFileStorageExportSetMapOutputWithContext(ctx context.Context) FileStorageExportSetMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileStorageExportSetMapOutput)
}

type FileStorageExportSetOutput struct {
	*pulumi.OutputState
}

func (FileStorageExportSetOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*FileStorageExportSet)(nil))
}

func (o FileStorageExportSetOutput) ToFileStorageExportSetOutput() FileStorageExportSetOutput {
	return o
}

func (o FileStorageExportSetOutput) ToFileStorageExportSetOutputWithContext(ctx context.Context) FileStorageExportSetOutput {
	return o
}

func (o FileStorageExportSetOutput) ToFileStorageExportSetPtrOutput() FileStorageExportSetPtrOutput {
	return o.ToFileStorageExportSetPtrOutputWithContext(context.Background())
}

func (o FileStorageExportSetOutput) ToFileStorageExportSetPtrOutputWithContext(ctx context.Context) FileStorageExportSetPtrOutput {
	return o.ApplyT(func(v FileStorageExportSet) *FileStorageExportSet {
		return &v
	}).(FileStorageExportSetPtrOutput)
}

type FileStorageExportSetPtrOutput struct {
	*pulumi.OutputState
}

func (FileStorageExportSetPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**FileStorageExportSet)(nil))
}

func (o FileStorageExportSetPtrOutput) ToFileStorageExportSetPtrOutput() FileStorageExportSetPtrOutput {
	return o
}

func (o FileStorageExportSetPtrOutput) ToFileStorageExportSetPtrOutputWithContext(ctx context.Context) FileStorageExportSetPtrOutput {
	return o
}

type FileStorageExportSetArrayOutput struct{ *pulumi.OutputState }

func (FileStorageExportSetArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]FileStorageExportSet)(nil))
}

func (o FileStorageExportSetArrayOutput) ToFileStorageExportSetArrayOutput() FileStorageExportSetArrayOutput {
	return o
}

func (o FileStorageExportSetArrayOutput) ToFileStorageExportSetArrayOutputWithContext(ctx context.Context) FileStorageExportSetArrayOutput {
	return o
}

func (o FileStorageExportSetArrayOutput) Index(i pulumi.IntInput) FileStorageExportSetOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) FileStorageExportSet {
		return vs[0].([]FileStorageExportSet)[vs[1].(int)]
	}).(FileStorageExportSetOutput)
}

type FileStorageExportSetMapOutput struct{ *pulumi.OutputState }

func (FileStorageExportSetMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]FileStorageExportSet)(nil))
}

func (o FileStorageExportSetMapOutput) ToFileStorageExportSetMapOutput() FileStorageExportSetMapOutput {
	return o
}

func (o FileStorageExportSetMapOutput) ToFileStorageExportSetMapOutputWithContext(ctx context.Context) FileStorageExportSetMapOutput {
	return o
}

func (o FileStorageExportSetMapOutput) MapIndex(k pulumi.StringInput) FileStorageExportSetOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) FileStorageExportSet {
		return vs[0].(map[string]FileStorageExportSet)[vs[1].(string)]
	}).(FileStorageExportSetOutput)
}

func init() {
	pulumi.RegisterOutputType(FileStorageExportSetOutput{})
	pulumi.RegisterOutputType(FileStorageExportSetPtrOutput{})
	pulumi.RegisterOutputType(FileStorageExportSetArrayOutput{})
	pulumi.RegisterOutputType(FileStorageExportSetMapOutput{})
}
