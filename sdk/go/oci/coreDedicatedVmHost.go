// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Dedicated Vm Host resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new dedicated virtual machine host in the specified compartment and the specified availability domain.
// Dedicated virtual machine hosts enable you to run your Compute virtual machine (VM) instances on dedicated servers
// that are a single tenant and not shared with other customers.
// For more information, see [Dedicated Virtual Machine Hosts](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/dedicatedvmhosts.htm).
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
// 		_, err := oci.NewCoreDedicatedVmHost(ctx, "testDedicatedVmHost", &oci.CoreDedicatedVmHostArgs{
// 			AvailabilityDomain:   pulumi.Any(_var.Dedicated_vm_host_availability_domain),
// 			CompartmentId:        pulumi.Any(_var.Compartment_id),
// 			DedicatedVmHostShape: pulumi.Any(_var.Dedicated_vm_host_dedicated_vm_host_shape),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			DisplayName: pulumi.Any(_var.Dedicated_vm_host_display_name),
// 			FaultDomain: pulumi.Any(_var.Dedicated_vm_host_fault_domain),
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
// DedicatedVmHosts can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/coreDedicatedVmHost:CoreDedicatedVmHost test_dedicated_vm_host "id"
// ```
type CoreDedicatedVmHost struct {
	pulumi.CustomResourceState

	// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringOutput `pulumi:"availabilityDomain"`
	// (Updatable) The OCID of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
	DedicatedVmHostShape pulumi.StringOutput `pulumi:"dedicatedVmHostShape"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My dedicated VM host`
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
	FaultDomain pulumi.StringOutput `pulumi:"faultDomain"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The current available memory of the dedicated VM host, in GBs.
	RemainingMemoryInGbs pulumi.Float64Output `pulumi:"remainingMemoryInGbs"`
	// The current available OCPUs of the dedicated VM host.
	RemainingOcpus pulumi.Float64Output `pulumi:"remainingOcpus"`
	// The current state of the dedicated VM host.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The current total memory of the dedicated VM host, in GBs.
	TotalMemoryInGbs pulumi.Float64Output `pulumi:"totalMemoryInGbs"`
	// The current total OCPUs of the dedicated VM host.
	TotalOcpus pulumi.Float64Output `pulumi:"totalOcpus"`
}

// NewCoreDedicatedVmHost registers a new resource with the given unique name, arguments, and options.
func NewCoreDedicatedVmHost(ctx *pulumi.Context,
	name string, args *CoreDedicatedVmHostArgs, opts ...pulumi.ResourceOption) (*CoreDedicatedVmHost, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AvailabilityDomain == nil {
		return nil, errors.New("invalid value for required argument 'AvailabilityDomain'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DedicatedVmHostShape == nil {
		return nil, errors.New("invalid value for required argument 'DedicatedVmHostShape'")
	}
	var resource CoreDedicatedVmHost
	err := ctx.RegisterResource("oci:index/coreDedicatedVmHost:CoreDedicatedVmHost", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCoreDedicatedVmHost gets an existing CoreDedicatedVmHost resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCoreDedicatedVmHost(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CoreDedicatedVmHostState, opts ...pulumi.ResourceOption) (*CoreDedicatedVmHost, error) {
	var resource CoreDedicatedVmHost
	err := ctx.ReadResource("oci:index/coreDedicatedVmHost:CoreDedicatedVmHost", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CoreDedicatedVmHost resources.
type coreDedicatedVmHostState struct {
	// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// (Updatable) The OCID of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
	DedicatedVmHostShape *string `pulumi:"dedicatedVmHostShape"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My dedicated VM host`
	DisplayName *string `pulumi:"displayName"`
	// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
	FaultDomain *string `pulumi:"faultDomain"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The current available memory of the dedicated VM host, in GBs.
	RemainingMemoryInGbs *float64 `pulumi:"remainingMemoryInGbs"`
	// The current available OCPUs of the dedicated VM host.
	RemainingOcpus *float64 `pulumi:"remainingOcpus"`
	// The current state of the dedicated VM host.
	State *string `pulumi:"state"`
	// The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The current total memory of the dedicated VM host, in GBs.
	TotalMemoryInGbs *float64 `pulumi:"totalMemoryInGbs"`
	// The current total OCPUs of the dedicated VM host.
	TotalOcpus *float64 `pulumi:"totalOcpus"`
}

type CoreDedicatedVmHostState struct {
	// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment.
	CompartmentId pulumi.StringPtrInput
	// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
	DedicatedVmHostShape pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My dedicated VM host`
	DisplayName pulumi.StringPtrInput
	// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
	FaultDomain pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The current available memory of the dedicated VM host, in GBs.
	RemainingMemoryInGbs pulumi.Float64PtrInput
	// The current available OCPUs of the dedicated VM host.
	RemainingOcpus pulumi.Float64PtrInput
	// The current state of the dedicated VM host.
	State pulumi.StringPtrInput
	// The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The current total memory of the dedicated VM host, in GBs.
	TotalMemoryInGbs pulumi.Float64PtrInput
	// The current total OCPUs of the dedicated VM host.
	TotalOcpus pulumi.Float64PtrInput
}

func (CoreDedicatedVmHostState) ElementType() reflect.Type {
	return reflect.TypeOf((*coreDedicatedVmHostState)(nil)).Elem()
}

type coreDedicatedVmHostArgs struct {
	// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// (Updatable) The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
	DedicatedVmHostShape string `pulumi:"dedicatedVmHostShape"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My dedicated VM host`
	DisplayName *string `pulumi:"displayName"`
	// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
	FaultDomain *string `pulumi:"faultDomain"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
}

// The set of arguments for constructing a CoreDedicatedVmHost resource.
type CoreDedicatedVmHostArgs struct {
	// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringInput
	// (Updatable) The OCID of the compartment.
	CompartmentId pulumi.StringInput
	// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
	DedicatedVmHostShape pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My dedicated VM host`
	DisplayName pulumi.StringPtrInput
	// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
	FaultDomain pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
}

func (CoreDedicatedVmHostArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*coreDedicatedVmHostArgs)(nil)).Elem()
}

type CoreDedicatedVmHostInput interface {
	pulumi.Input

	ToCoreDedicatedVmHostOutput() CoreDedicatedVmHostOutput
	ToCoreDedicatedVmHostOutputWithContext(ctx context.Context) CoreDedicatedVmHostOutput
}

func (*CoreDedicatedVmHost) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreDedicatedVmHost)(nil))
}

func (i *CoreDedicatedVmHost) ToCoreDedicatedVmHostOutput() CoreDedicatedVmHostOutput {
	return i.ToCoreDedicatedVmHostOutputWithContext(context.Background())
}

func (i *CoreDedicatedVmHost) ToCoreDedicatedVmHostOutputWithContext(ctx context.Context) CoreDedicatedVmHostOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDedicatedVmHostOutput)
}

func (i *CoreDedicatedVmHost) ToCoreDedicatedVmHostPtrOutput() CoreDedicatedVmHostPtrOutput {
	return i.ToCoreDedicatedVmHostPtrOutputWithContext(context.Background())
}

func (i *CoreDedicatedVmHost) ToCoreDedicatedVmHostPtrOutputWithContext(ctx context.Context) CoreDedicatedVmHostPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDedicatedVmHostPtrOutput)
}

type CoreDedicatedVmHostPtrInput interface {
	pulumi.Input

	ToCoreDedicatedVmHostPtrOutput() CoreDedicatedVmHostPtrOutput
	ToCoreDedicatedVmHostPtrOutputWithContext(ctx context.Context) CoreDedicatedVmHostPtrOutput
}

type coreDedicatedVmHostPtrType CoreDedicatedVmHostArgs

func (*coreDedicatedVmHostPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreDedicatedVmHost)(nil))
}

func (i *coreDedicatedVmHostPtrType) ToCoreDedicatedVmHostPtrOutput() CoreDedicatedVmHostPtrOutput {
	return i.ToCoreDedicatedVmHostPtrOutputWithContext(context.Background())
}

func (i *coreDedicatedVmHostPtrType) ToCoreDedicatedVmHostPtrOutputWithContext(ctx context.Context) CoreDedicatedVmHostPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDedicatedVmHostPtrOutput)
}

// CoreDedicatedVmHostArrayInput is an input type that accepts CoreDedicatedVmHostArray and CoreDedicatedVmHostArrayOutput values.
// You can construct a concrete instance of `CoreDedicatedVmHostArrayInput` via:
//
//          CoreDedicatedVmHostArray{ CoreDedicatedVmHostArgs{...} }
type CoreDedicatedVmHostArrayInput interface {
	pulumi.Input

	ToCoreDedicatedVmHostArrayOutput() CoreDedicatedVmHostArrayOutput
	ToCoreDedicatedVmHostArrayOutputWithContext(context.Context) CoreDedicatedVmHostArrayOutput
}

type CoreDedicatedVmHostArray []CoreDedicatedVmHostInput

func (CoreDedicatedVmHostArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CoreDedicatedVmHost)(nil)).Elem()
}

func (i CoreDedicatedVmHostArray) ToCoreDedicatedVmHostArrayOutput() CoreDedicatedVmHostArrayOutput {
	return i.ToCoreDedicatedVmHostArrayOutputWithContext(context.Background())
}

func (i CoreDedicatedVmHostArray) ToCoreDedicatedVmHostArrayOutputWithContext(ctx context.Context) CoreDedicatedVmHostArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDedicatedVmHostArrayOutput)
}

// CoreDedicatedVmHostMapInput is an input type that accepts CoreDedicatedVmHostMap and CoreDedicatedVmHostMapOutput values.
// You can construct a concrete instance of `CoreDedicatedVmHostMapInput` via:
//
//          CoreDedicatedVmHostMap{ "key": CoreDedicatedVmHostArgs{...} }
type CoreDedicatedVmHostMapInput interface {
	pulumi.Input

	ToCoreDedicatedVmHostMapOutput() CoreDedicatedVmHostMapOutput
	ToCoreDedicatedVmHostMapOutputWithContext(context.Context) CoreDedicatedVmHostMapOutput
}

type CoreDedicatedVmHostMap map[string]CoreDedicatedVmHostInput

func (CoreDedicatedVmHostMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CoreDedicatedVmHost)(nil)).Elem()
}

func (i CoreDedicatedVmHostMap) ToCoreDedicatedVmHostMapOutput() CoreDedicatedVmHostMapOutput {
	return i.ToCoreDedicatedVmHostMapOutputWithContext(context.Background())
}

func (i CoreDedicatedVmHostMap) ToCoreDedicatedVmHostMapOutputWithContext(ctx context.Context) CoreDedicatedVmHostMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDedicatedVmHostMapOutput)
}

type CoreDedicatedVmHostOutput struct {
	*pulumi.OutputState
}

func (CoreDedicatedVmHostOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreDedicatedVmHost)(nil))
}

func (o CoreDedicatedVmHostOutput) ToCoreDedicatedVmHostOutput() CoreDedicatedVmHostOutput {
	return o
}

func (o CoreDedicatedVmHostOutput) ToCoreDedicatedVmHostOutputWithContext(ctx context.Context) CoreDedicatedVmHostOutput {
	return o
}

func (o CoreDedicatedVmHostOutput) ToCoreDedicatedVmHostPtrOutput() CoreDedicatedVmHostPtrOutput {
	return o.ToCoreDedicatedVmHostPtrOutputWithContext(context.Background())
}

func (o CoreDedicatedVmHostOutput) ToCoreDedicatedVmHostPtrOutputWithContext(ctx context.Context) CoreDedicatedVmHostPtrOutput {
	return o.ApplyT(func(v CoreDedicatedVmHost) *CoreDedicatedVmHost {
		return &v
	}).(CoreDedicatedVmHostPtrOutput)
}

type CoreDedicatedVmHostPtrOutput struct {
	*pulumi.OutputState
}

func (CoreDedicatedVmHostPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreDedicatedVmHost)(nil))
}

func (o CoreDedicatedVmHostPtrOutput) ToCoreDedicatedVmHostPtrOutput() CoreDedicatedVmHostPtrOutput {
	return o
}

func (o CoreDedicatedVmHostPtrOutput) ToCoreDedicatedVmHostPtrOutputWithContext(ctx context.Context) CoreDedicatedVmHostPtrOutput {
	return o
}

type CoreDedicatedVmHostArrayOutput struct{ *pulumi.OutputState }

func (CoreDedicatedVmHostArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CoreDedicatedVmHost)(nil))
}

func (o CoreDedicatedVmHostArrayOutput) ToCoreDedicatedVmHostArrayOutput() CoreDedicatedVmHostArrayOutput {
	return o
}

func (o CoreDedicatedVmHostArrayOutput) ToCoreDedicatedVmHostArrayOutputWithContext(ctx context.Context) CoreDedicatedVmHostArrayOutput {
	return o
}

func (o CoreDedicatedVmHostArrayOutput) Index(i pulumi.IntInput) CoreDedicatedVmHostOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CoreDedicatedVmHost {
		return vs[0].([]CoreDedicatedVmHost)[vs[1].(int)]
	}).(CoreDedicatedVmHostOutput)
}

type CoreDedicatedVmHostMapOutput struct{ *pulumi.OutputState }

func (CoreDedicatedVmHostMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CoreDedicatedVmHost)(nil))
}

func (o CoreDedicatedVmHostMapOutput) ToCoreDedicatedVmHostMapOutput() CoreDedicatedVmHostMapOutput {
	return o
}

func (o CoreDedicatedVmHostMapOutput) ToCoreDedicatedVmHostMapOutputWithContext(ctx context.Context) CoreDedicatedVmHostMapOutput {
	return o
}

func (o CoreDedicatedVmHostMapOutput) MapIndex(k pulumi.StringInput) CoreDedicatedVmHostOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CoreDedicatedVmHost {
		return vs[0].(map[string]CoreDedicatedVmHost)[vs[1].(string)]
	}).(CoreDedicatedVmHostOutput)
}

func init() {
	pulumi.RegisterOutputType(CoreDedicatedVmHostOutput{})
	pulumi.RegisterOutputType(CoreDedicatedVmHostPtrOutput{})
	pulumi.RegisterOutputType(CoreDedicatedVmHostArrayOutput{})
	pulumi.RegisterOutputType(CoreDedicatedVmHostMapOutput{})
}
