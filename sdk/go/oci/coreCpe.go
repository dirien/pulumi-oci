// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Cpe resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new virtual customer-premises equipment (CPE) object in the specified compartment. For
// more information, see [IPSec VPNs](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingIPsec.htm).
//
// For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want
// the CPE to reside. Notice that the CPE doesn't have to be in the same compartment as the IPSec
// connection or other Networking Service components. If you're not sure which compartment to
// use, put the CPE in the same compartment as the DRG. For more information about
// compartments and access control, see [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
// For information about OCIDs, see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
//
// You must provide the public IP address of your on-premises router. See
// [Configuring Your On-Premises Router for an IPSec VPN](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/configuringCPE.htm).
//
// You may optionally specify a *display name* for the CPE, otherwise a default is provided. It does not have to
// be unique, and you can change it. Avoid entering confidential information.
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
// 		_, err := oci.NewCoreCpe(ctx, "testCpe", &oci.CoreCpeArgs{
// 			CompartmentId:    pulumi.Any(_var.Compartment_id),
// 			IpAddress:        pulumi.Any(_var.Cpe_ip_address),
// 			CpeDeviceShapeId: pulumi.Any(data.Oci_core_cpe_device_shapes.Test_cpe_device_shapes.Cpe_device_shapes[0].Cpe_device_shape_id),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			DisplayName: pulumi.Any(_var.Cpe_display_name),
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
// Cpes can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/coreCpe:CoreCpe test_cpe "id"
// ```
type CoreCpe struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment to contain the CPE.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CPE device type. You can provide a value if you want to later generate CPE device configuration content for IPSec connections that use this CPE. You can also call [UpdateCpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/UpdateCpe) later to provide a value. For a list of possible values, see [ListCpeDeviceShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CpeDeviceShapeSummary/ListCpeDeviceShapes).
	CpeDeviceShapeId pulumi.StringOutput `pulumi:"cpeDeviceShapeId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The public IP address of the on-premises router.  Example: `203.0.113.2`
	IpAddress pulumi.StringOutput `pulumi:"ipAddress"`
	// The date and time the CPE was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewCoreCpe registers a new resource with the given unique name, arguments, and options.
func NewCoreCpe(ctx *pulumi.Context,
	name string, args *CoreCpeArgs, opts ...pulumi.ResourceOption) (*CoreCpe, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.IpAddress == nil {
		return nil, errors.New("invalid value for required argument 'IpAddress'")
	}
	var resource CoreCpe
	err := ctx.RegisterResource("oci:index/coreCpe:CoreCpe", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCoreCpe gets an existing CoreCpe resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCoreCpe(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CoreCpeState, opts ...pulumi.ResourceOption) (*CoreCpe, error) {
	var resource CoreCpe
	err := ctx.ReadResource("oci:index/coreCpe:CoreCpe", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CoreCpe resources.
type coreCpeState struct {
	// (Updatable) The OCID of the compartment to contain the CPE.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CPE device type. You can provide a value if you want to later generate CPE device configuration content for IPSec connections that use this CPE. You can also call [UpdateCpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/UpdateCpe) later to provide a value. For a list of possible values, see [ListCpeDeviceShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CpeDeviceShapeSummary/ListCpeDeviceShapes).
	CpeDeviceShapeId *string `pulumi:"cpeDeviceShapeId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The public IP address of the on-premises router.  Example: `203.0.113.2`
	IpAddress *string `pulumi:"ipAddress"`
	// The date and time the CPE was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type CoreCpeState struct {
	// (Updatable) The OCID of the compartment to contain the CPE.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CPE device type. You can provide a value if you want to later generate CPE device configuration content for IPSec connections that use this CPE. You can also call [UpdateCpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/UpdateCpe) later to provide a value. For a list of possible values, see [ListCpeDeviceShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CpeDeviceShapeSummary/ListCpeDeviceShapes).
	CpeDeviceShapeId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The public IP address of the on-premises router.  Example: `203.0.113.2`
	IpAddress pulumi.StringPtrInput
	// The date and time the CPE was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (CoreCpeState) ElementType() reflect.Type {
	return reflect.TypeOf((*coreCpeState)(nil)).Elem()
}

type coreCpeArgs struct {
	// (Updatable) The OCID of the compartment to contain the CPE.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CPE device type. You can provide a value if you want to later generate CPE device configuration content for IPSec connections that use this CPE. You can also call [UpdateCpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/UpdateCpe) later to provide a value. For a list of possible values, see [ListCpeDeviceShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CpeDeviceShapeSummary/ListCpeDeviceShapes).
	CpeDeviceShapeId *string `pulumi:"cpeDeviceShapeId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The public IP address of the on-premises router.  Example: `203.0.113.2`
	IpAddress string `pulumi:"ipAddress"`
}

// The set of arguments for constructing a CoreCpe resource.
type CoreCpeArgs struct {
	// (Updatable) The OCID of the compartment to contain the CPE.
	CompartmentId pulumi.StringInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CPE device type. You can provide a value if you want to later generate CPE device configuration content for IPSec connections that use this CPE. You can also call [UpdateCpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/UpdateCpe) later to provide a value. For a list of possible values, see [ListCpeDeviceShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CpeDeviceShapeSummary/ListCpeDeviceShapes).
	CpeDeviceShapeId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The public IP address of the on-premises router.  Example: `203.0.113.2`
	IpAddress pulumi.StringInput
}

func (CoreCpeArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*coreCpeArgs)(nil)).Elem()
}

type CoreCpeInput interface {
	pulumi.Input

	ToCoreCpeOutput() CoreCpeOutput
	ToCoreCpeOutputWithContext(ctx context.Context) CoreCpeOutput
}

func (*CoreCpe) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreCpe)(nil))
}

func (i *CoreCpe) ToCoreCpeOutput() CoreCpeOutput {
	return i.ToCoreCpeOutputWithContext(context.Background())
}

func (i *CoreCpe) ToCoreCpeOutputWithContext(ctx context.Context) CoreCpeOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreCpeOutput)
}

func (i *CoreCpe) ToCoreCpePtrOutput() CoreCpePtrOutput {
	return i.ToCoreCpePtrOutputWithContext(context.Background())
}

func (i *CoreCpe) ToCoreCpePtrOutputWithContext(ctx context.Context) CoreCpePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreCpePtrOutput)
}

type CoreCpePtrInput interface {
	pulumi.Input

	ToCoreCpePtrOutput() CoreCpePtrOutput
	ToCoreCpePtrOutputWithContext(ctx context.Context) CoreCpePtrOutput
}

type coreCpePtrType CoreCpeArgs

func (*coreCpePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreCpe)(nil))
}

func (i *coreCpePtrType) ToCoreCpePtrOutput() CoreCpePtrOutput {
	return i.ToCoreCpePtrOutputWithContext(context.Background())
}

func (i *coreCpePtrType) ToCoreCpePtrOutputWithContext(ctx context.Context) CoreCpePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreCpePtrOutput)
}

// CoreCpeArrayInput is an input type that accepts CoreCpeArray and CoreCpeArrayOutput values.
// You can construct a concrete instance of `CoreCpeArrayInput` via:
//
//          CoreCpeArray{ CoreCpeArgs{...} }
type CoreCpeArrayInput interface {
	pulumi.Input

	ToCoreCpeArrayOutput() CoreCpeArrayOutput
	ToCoreCpeArrayOutputWithContext(context.Context) CoreCpeArrayOutput
}

type CoreCpeArray []CoreCpeInput

func (CoreCpeArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CoreCpe)(nil)).Elem()
}

func (i CoreCpeArray) ToCoreCpeArrayOutput() CoreCpeArrayOutput {
	return i.ToCoreCpeArrayOutputWithContext(context.Background())
}

func (i CoreCpeArray) ToCoreCpeArrayOutputWithContext(ctx context.Context) CoreCpeArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreCpeArrayOutput)
}

// CoreCpeMapInput is an input type that accepts CoreCpeMap and CoreCpeMapOutput values.
// You can construct a concrete instance of `CoreCpeMapInput` via:
//
//          CoreCpeMap{ "key": CoreCpeArgs{...} }
type CoreCpeMapInput interface {
	pulumi.Input

	ToCoreCpeMapOutput() CoreCpeMapOutput
	ToCoreCpeMapOutputWithContext(context.Context) CoreCpeMapOutput
}

type CoreCpeMap map[string]CoreCpeInput

func (CoreCpeMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CoreCpe)(nil)).Elem()
}

func (i CoreCpeMap) ToCoreCpeMapOutput() CoreCpeMapOutput {
	return i.ToCoreCpeMapOutputWithContext(context.Background())
}

func (i CoreCpeMap) ToCoreCpeMapOutputWithContext(ctx context.Context) CoreCpeMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreCpeMapOutput)
}

type CoreCpeOutput struct {
	*pulumi.OutputState
}

func (CoreCpeOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreCpe)(nil))
}

func (o CoreCpeOutput) ToCoreCpeOutput() CoreCpeOutput {
	return o
}

func (o CoreCpeOutput) ToCoreCpeOutputWithContext(ctx context.Context) CoreCpeOutput {
	return o
}

func (o CoreCpeOutput) ToCoreCpePtrOutput() CoreCpePtrOutput {
	return o.ToCoreCpePtrOutputWithContext(context.Background())
}

func (o CoreCpeOutput) ToCoreCpePtrOutputWithContext(ctx context.Context) CoreCpePtrOutput {
	return o.ApplyT(func(v CoreCpe) *CoreCpe {
		return &v
	}).(CoreCpePtrOutput)
}

type CoreCpePtrOutput struct {
	*pulumi.OutputState
}

func (CoreCpePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreCpe)(nil))
}

func (o CoreCpePtrOutput) ToCoreCpePtrOutput() CoreCpePtrOutput {
	return o
}

func (o CoreCpePtrOutput) ToCoreCpePtrOutputWithContext(ctx context.Context) CoreCpePtrOutput {
	return o
}

type CoreCpeArrayOutput struct{ *pulumi.OutputState }

func (CoreCpeArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CoreCpe)(nil))
}

func (o CoreCpeArrayOutput) ToCoreCpeArrayOutput() CoreCpeArrayOutput {
	return o
}

func (o CoreCpeArrayOutput) ToCoreCpeArrayOutputWithContext(ctx context.Context) CoreCpeArrayOutput {
	return o
}

func (o CoreCpeArrayOutput) Index(i pulumi.IntInput) CoreCpeOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CoreCpe {
		return vs[0].([]CoreCpe)[vs[1].(int)]
	}).(CoreCpeOutput)
}

type CoreCpeMapOutput struct{ *pulumi.OutputState }

func (CoreCpeMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CoreCpe)(nil))
}

func (o CoreCpeMapOutput) ToCoreCpeMapOutput() CoreCpeMapOutput {
	return o
}

func (o CoreCpeMapOutput) ToCoreCpeMapOutputWithContext(ctx context.Context) CoreCpeMapOutput {
	return o
}

func (o CoreCpeMapOutput) MapIndex(k pulumi.StringInput) CoreCpeOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CoreCpe {
		return vs[0].(map[string]CoreCpe)[vs[1].(string)]
	}).(CoreCpeOutput)
}

func init() {
	pulumi.RegisterOutputType(CoreCpeOutput{})
	pulumi.RegisterOutputType(CoreCpePtrOutput{})
	pulumi.RegisterOutputType(CoreCpeArrayOutput{})
	pulumi.RegisterOutputType(CoreCpeMapOutput{})
}
