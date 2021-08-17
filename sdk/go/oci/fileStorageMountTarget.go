// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Mount Target resource in Oracle Cloud Infrastructure File Storage service.
//
// Creates a new mount target in the specified compartment and
// subnet. You can associate a file system with a mount
// target only when they exist in the same availability domain. Instances
// can connect to mount targets in another availablity domain, but
// you might see higher latency than with instances in the same
// availability domain as the mount target.
//
// Mount targets have one or more private IP addresses that you can
// provide as the host portion of remote target parameters in
// client mount commands. These private IP addresses are listed
// in the privateIpIds property of the mount target and are highly available. Mount
// targets also consume additional IP addresses in their subnet.
// Do not use /30 or smaller subnets for mount target creation because they
// do not have sufficient available IP addresses.
// Allow at least three IP addresses for each mount target.
//
// For information about access control and compartments, see
// [Overview of the IAM
// Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
//
// For information about availability domains, see [Regions and
// Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm).
// To get a list of availability domains, use the
// `ListAvailabilityDomains` operation in the Identity and Access
// Management Service API.
//
// All Oracle Cloud Infrastructure Services resources, including
// mount targets, get an Oracle-assigned, unique ID called an
// Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).\
// When you create a resource, you can find its OCID in the response.
// You can also retrieve a resource's OCID by using a List API operation on that resource
// type, or by viewing the resource in the Console.
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
// 		_, err := oci.NewFileStorageMountTarget(ctx, "testMountTarget", &oci.FileStorageMountTargetArgs{
// 			AvailabilityDomain: pulumi.Any(_var.Mount_target_availability_domain),
// 			CompartmentId:      pulumi.Any(_var.Compartment_id),
// 			SubnetId:           pulumi.Any(oci_core_subnet.Test_subnet.Id),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			DisplayName: pulumi.Any(_var.Mount_target_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
// 			HostnameLabel: pulumi.Any(_var.Mount_target_hostname_label),
// 			IpAddress:     pulumi.Any(_var.Mount_target_ip_address),
// 			NsgIds:        pulumi.Any(_var.Mount_target_nsg_ids),
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
// MountTargets can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/fileStorageMountTarget:FileStorageMountTarget test_mount_target "id"
// ```
type FileStorageMountTarget struct {
	pulumi.CustomResourceState

	// The availability domain in which to create the mount target.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringOutput `pulumi:"availabilityDomain"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the mount target.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My mount target`
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated export set. Controls what file systems will be exported through Network File System (NFS) protocol on this mount target.
	ExportSetId pulumi.StringOutput `pulumi:"exportSetId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The hostname for the mount target's IP address, used for DNS resolution. The value is the hostname portion of the private IP address's fully qualified domain name (FQDN). For example, `files-1` in the FQDN `files-1.subnet123.vcn1.oraclevcn.com`. Must be unique across all VNICs in the subnet and comply with [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123).
	HostnameLabel pulumi.StringOutput `pulumi:"hostnameLabel"`
	// A private IP address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns a private IP address from the subnet.  Example: `10.0.3.3`
	IpAddress pulumi.StringOutput `pulumi:"ipAddress"`
	// Additional information about the current 'lifecycleState'.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this mount target. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the mount target from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
	NsgIds pulumi.StringArrayOutput `pulumi:"nsgIds"`
	// The OCIDs of the private IP addresses associated with this mount target.
	PrivateIpIds pulumi.StringArrayOutput `pulumi:"privateIpIds"`
	// The current state of the mount target.
	State pulumi.StringOutput `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which to create the mount target.
	SubnetId pulumi.StringOutput `pulumi:"subnetId"`
	// The date and time the mount target was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewFileStorageMountTarget registers a new resource with the given unique name, arguments, and options.
func NewFileStorageMountTarget(ctx *pulumi.Context,
	name string, args *FileStorageMountTargetArgs, opts ...pulumi.ResourceOption) (*FileStorageMountTarget, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AvailabilityDomain == nil {
		return nil, errors.New("invalid value for required argument 'AvailabilityDomain'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.SubnetId == nil {
		return nil, errors.New("invalid value for required argument 'SubnetId'")
	}
	var resource FileStorageMountTarget
	err := ctx.RegisterResource("oci:index/fileStorageMountTarget:FileStorageMountTarget", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetFileStorageMountTarget gets an existing FileStorageMountTarget resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetFileStorageMountTarget(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *FileStorageMountTargetState, opts ...pulumi.ResourceOption) (*FileStorageMountTarget, error) {
	var resource FileStorageMountTarget
	err := ctx.ReadResource("oci:index/fileStorageMountTarget:FileStorageMountTarget", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering FileStorageMountTarget resources.
type fileStorageMountTargetState struct {
	// The availability domain in which to create the mount target.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the mount target.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My mount target`
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated export set. Controls what file systems will be exported through Network File System (NFS) protocol on this mount target.
	ExportSetId *string `pulumi:"exportSetId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The hostname for the mount target's IP address, used for DNS resolution. The value is the hostname portion of the private IP address's fully qualified domain name (FQDN). For example, `files-1` in the FQDN `files-1.subnet123.vcn1.oraclevcn.com`. Must be unique across all VNICs in the subnet and comply with [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123).
	HostnameLabel *string `pulumi:"hostnameLabel"`
	// A private IP address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns a private IP address from the subnet.  Example: `10.0.3.3`
	IpAddress *string `pulumi:"ipAddress"`
	// Additional information about the current 'lifecycleState'.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this mount target. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the mount target from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
	NsgIds []string `pulumi:"nsgIds"`
	// The OCIDs of the private IP addresses associated with this mount target.
	PrivateIpIds []string `pulumi:"privateIpIds"`
	// The current state of the mount target.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which to create the mount target.
	SubnetId *string `pulumi:"subnetId"`
	// The date and time the mount target was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type FileStorageMountTargetState struct {
	// The availability domain in which to create the mount target.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the mount target.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My mount target`
	DisplayName pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated export set. Controls what file systems will be exported through Network File System (NFS) protocol on this mount target.
	ExportSetId pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The hostname for the mount target's IP address, used for DNS resolution. The value is the hostname portion of the private IP address's fully qualified domain name (FQDN). For example, `files-1` in the FQDN `files-1.subnet123.vcn1.oraclevcn.com`. Must be unique across all VNICs in the subnet and comply with [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123).
	HostnameLabel pulumi.StringPtrInput
	// A private IP address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns a private IP address from the subnet.  Example: `10.0.3.3`
	IpAddress pulumi.StringPtrInput
	// Additional information about the current 'lifecycleState'.
	LifecycleDetails pulumi.StringPtrInput
	// (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this mount target. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the mount target from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
	NsgIds pulumi.StringArrayInput
	// The OCIDs of the private IP addresses associated with this mount target.
	PrivateIpIds pulumi.StringArrayInput
	// The current state of the mount target.
	State pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which to create the mount target.
	SubnetId pulumi.StringPtrInput
	// The date and time the mount target was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (FileStorageMountTargetState) ElementType() reflect.Type {
	return reflect.TypeOf((*fileStorageMountTargetState)(nil)).Elem()
}

type fileStorageMountTargetArgs struct {
	// The availability domain in which to create the mount target.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the mount target.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My mount target`
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The hostname for the mount target's IP address, used for DNS resolution. The value is the hostname portion of the private IP address's fully qualified domain name (FQDN). For example, `files-1` in the FQDN `files-1.subnet123.vcn1.oraclevcn.com`. Must be unique across all VNICs in the subnet and comply with [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123).
	HostnameLabel *string `pulumi:"hostnameLabel"`
	// A private IP address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns a private IP address from the subnet.  Example: `10.0.3.3`
	IpAddress *string `pulumi:"ipAddress"`
	// (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this mount target. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the mount target from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
	NsgIds []string `pulumi:"nsgIds"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which to create the mount target.
	SubnetId string `pulumi:"subnetId"`
}

// The set of arguments for constructing a FileStorageMountTarget resource.
type FileStorageMountTargetArgs struct {
	// The availability domain in which to create the mount target.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the mount target.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My mount target`
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The hostname for the mount target's IP address, used for DNS resolution. The value is the hostname portion of the private IP address's fully qualified domain name (FQDN). For example, `files-1` in the FQDN `files-1.subnet123.vcn1.oraclevcn.com`. Must be unique across all VNICs in the subnet and comply with [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123).
	HostnameLabel pulumi.StringPtrInput
	// A private IP address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns a private IP address from the subnet.  Example: `10.0.3.3`
	IpAddress pulumi.StringPtrInput
	// (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this mount target. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the mount target from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
	NsgIds pulumi.StringArrayInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which to create the mount target.
	SubnetId pulumi.StringInput
}

func (FileStorageMountTargetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*fileStorageMountTargetArgs)(nil)).Elem()
}

type FileStorageMountTargetInput interface {
	pulumi.Input

	ToFileStorageMountTargetOutput() FileStorageMountTargetOutput
	ToFileStorageMountTargetOutputWithContext(ctx context.Context) FileStorageMountTargetOutput
}

func (*FileStorageMountTarget) ElementType() reflect.Type {
	return reflect.TypeOf((*FileStorageMountTarget)(nil))
}

func (i *FileStorageMountTarget) ToFileStorageMountTargetOutput() FileStorageMountTargetOutput {
	return i.ToFileStorageMountTargetOutputWithContext(context.Background())
}

func (i *FileStorageMountTarget) ToFileStorageMountTargetOutputWithContext(ctx context.Context) FileStorageMountTargetOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileStorageMountTargetOutput)
}

func (i *FileStorageMountTarget) ToFileStorageMountTargetPtrOutput() FileStorageMountTargetPtrOutput {
	return i.ToFileStorageMountTargetPtrOutputWithContext(context.Background())
}

func (i *FileStorageMountTarget) ToFileStorageMountTargetPtrOutputWithContext(ctx context.Context) FileStorageMountTargetPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileStorageMountTargetPtrOutput)
}

type FileStorageMountTargetPtrInput interface {
	pulumi.Input

	ToFileStorageMountTargetPtrOutput() FileStorageMountTargetPtrOutput
	ToFileStorageMountTargetPtrOutputWithContext(ctx context.Context) FileStorageMountTargetPtrOutput
}

type fileStorageMountTargetPtrType FileStorageMountTargetArgs

func (*fileStorageMountTargetPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**FileStorageMountTarget)(nil))
}

func (i *fileStorageMountTargetPtrType) ToFileStorageMountTargetPtrOutput() FileStorageMountTargetPtrOutput {
	return i.ToFileStorageMountTargetPtrOutputWithContext(context.Background())
}

func (i *fileStorageMountTargetPtrType) ToFileStorageMountTargetPtrOutputWithContext(ctx context.Context) FileStorageMountTargetPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileStorageMountTargetPtrOutput)
}

// FileStorageMountTargetArrayInput is an input type that accepts FileStorageMountTargetArray and FileStorageMountTargetArrayOutput values.
// You can construct a concrete instance of `FileStorageMountTargetArrayInput` via:
//
//          FileStorageMountTargetArray{ FileStorageMountTargetArgs{...} }
type FileStorageMountTargetArrayInput interface {
	pulumi.Input

	ToFileStorageMountTargetArrayOutput() FileStorageMountTargetArrayOutput
	ToFileStorageMountTargetArrayOutputWithContext(context.Context) FileStorageMountTargetArrayOutput
}

type FileStorageMountTargetArray []FileStorageMountTargetInput

func (FileStorageMountTargetArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*FileStorageMountTarget)(nil)).Elem()
}

func (i FileStorageMountTargetArray) ToFileStorageMountTargetArrayOutput() FileStorageMountTargetArrayOutput {
	return i.ToFileStorageMountTargetArrayOutputWithContext(context.Background())
}

func (i FileStorageMountTargetArray) ToFileStorageMountTargetArrayOutputWithContext(ctx context.Context) FileStorageMountTargetArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileStorageMountTargetArrayOutput)
}

// FileStorageMountTargetMapInput is an input type that accepts FileStorageMountTargetMap and FileStorageMountTargetMapOutput values.
// You can construct a concrete instance of `FileStorageMountTargetMapInput` via:
//
//          FileStorageMountTargetMap{ "key": FileStorageMountTargetArgs{...} }
type FileStorageMountTargetMapInput interface {
	pulumi.Input

	ToFileStorageMountTargetMapOutput() FileStorageMountTargetMapOutput
	ToFileStorageMountTargetMapOutputWithContext(context.Context) FileStorageMountTargetMapOutput
}

type FileStorageMountTargetMap map[string]FileStorageMountTargetInput

func (FileStorageMountTargetMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*FileStorageMountTarget)(nil)).Elem()
}

func (i FileStorageMountTargetMap) ToFileStorageMountTargetMapOutput() FileStorageMountTargetMapOutput {
	return i.ToFileStorageMountTargetMapOutputWithContext(context.Background())
}

func (i FileStorageMountTargetMap) ToFileStorageMountTargetMapOutputWithContext(ctx context.Context) FileStorageMountTargetMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileStorageMountTargetMapOutput)
}

type FileStorageMountTargetOutput struct {
	*pulumi.OutputState
}

func (FileStorageMountTargetOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*FileStorageMountTarget)(nil))
}

func (o FileStorageMountTargetOutput) ToFileStorageMountTargetOutput() FileStorageMountTargetOutput {
	return o
}

func (o FileStorageMountTargetOutput) ToFileStorageMountTargetOutputWithContext(ctx context.Context) FileStorageMountTargetOutput {
	return o
}

func (o FileStorageMountTargetOutput) ToFileStorageMountTargetPtrOutput() FileStorageMountTargetPtrOutput {
	return o.ToFileStorageMountTargetPtrOutputWithContext(context.Background())
}

func (o FileStorageMountTargetOutput) ToFileStorageMountTargetPtrOutputWithContext(ctx context.Context) FileStorageMountTargetPtrOutput {
	return o.ApplyT(func(v FileStorageMountTarget) *FileStorageMountTarget {
		return &v
	}).(FileStorageMountTargetPtrOutput)
}

type FileStorageMountTargetPtrOutput struct {
	*pulumi.OutputState
}

func (FileStorageMountTargetPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**FileStorageMountTarget)(nil))
}

func (o FileStorageMountTargetPtrOutput) ToFileStorageMountTargetPtrOutput() FileStorageMountTargetPtrOutput {
	return o
}

func (o FileStorageMountTargetPtrOutput) ToFileStorageMountTargetPtrOutputWithContext(ctx context.Context) FileStorageMountTargetPtrOutput {
	return o
}

type FileStorageMountTargetArrayOutput struct{ *pulumi.OutputState }

func (FileStorageMountTargetArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]FileStorageMountTarget)(nil))
}

func (o FileStorageMountTargetArrayOutput) ToFileStorageMountTargetArrayOutput() FileStorageMountTargetArrayOutput {
	return o
}

func (o FileStorageMountTargetArrayOutput) ToFileStorageMountTargetArrayOutputWithContext(ctx context.Context) FileStorageMountTargetArrayOutput {
	return o
}

func (o FileStorageMountTargetArrayOutput) Index(i pulumi.IntInput) FileStorageMountTargetOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) FileStorageMountTarget {
		return vs[0].([]FileStorageMountTarget)[vs[1].(int)]
	}).(FileStorageMountTargetOutput)
}

type FileStorageMountTargetMapOutput struct{ *pulumi.OutputState }

func (FileStorageMountTargetMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]FileStorageMountTarget)(nil))
}

func (o FileStorageMountTargetMapOutput) ToFileStorageMountTargetMapOutput() FileStorageMountTargetMapOutput {
	return o
}

func (o FileStorageMountTargetMapOutput) ToFileStorageMountTargetMapOutputWithContext(ctx context.Context) FileStorageMountTargetMapOutput {
	return o
}

func (o FileStorageMountTargetMapOutput) MapIndex(k pulumi.StringInput) FileStorageMountTargetOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) FileStorageMountTarget {
		return vs[0].(map[string]FileStorageMountTarget)[vs[1].(string)]
	}).(FileStorageMountTargetOutput)
}

func init() {
	pulumi.RegisterOutputType(FileStorageMountTargetOutput{})
	pulumi.RegisterOutputType(FileStorageMountTargetPtrOutput{})
	pulumi.RegisterOutputType(FileStorageMountTargetArrayOutput{})
	pulumi.RegisterOutputType(FileStorageMountTargetMapOutput{})
}