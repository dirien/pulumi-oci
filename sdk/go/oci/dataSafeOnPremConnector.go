// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the On Prem Connector resource in Oracle Cloud Infrastructure Data Safe service.
//
// Creates a new on-premises connector.
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
// 		_, err := oci.NewDataSafeOnPremConnector(ctx, "testOnPremConnector", &oci.DataSafeOnPremConnectorArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			Description: pulumi.Any(_var.On_prem_connector_description),
// 			DisplayName: pulumi.Any(_var.On_prem_connector_display_name),
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
// OnPremConnectors can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/dataSafeOnPremConnector:DataSafeOnPremConnector test_on_prem_connector "id"
// ```
type DataSafeOnPremConnector struct {
	pulumi.CustomResourceState

	// Latest available version of the on-premises connector.
	AvailableVersion pulumi.StringOutput `pulumi:"availableVersion"`
	// (Updatable) The OCID of the compartment where you want to create the on-premises connector.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Created version of the on-premises connector.
	CreatedVersion pulumi.StringOutput `pulumi:"createdVersion"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) The description of the on-premises connector.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The display name of the on-premises connector. The name does not have to be unique, and it's changeable.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// Details about the current state of the on-premises connector.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The current state of the on-premises connector.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The date and time the on-premises connector was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewDataSafeOnPremConnector registers a new resource with the given unique name, arguments, and options.
func NewDataSafeOnPremConnector(ctx *pulumi.Context,
	name string, args *DataSafeOnPremConnectorArgs, opts ...pulumi.ResourceOption) (*DataSafeOnPremConnector, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	var resource DataSafeOnPremConnector
	err := ctx.RegisterResource("oci:index/dataSafeOnPremConnector:DataSafeOnPremConnector", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDataSafeOnPremConnector gets an existing DataSafeOnPremConnector resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDataSafeOnPremConnector(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DataSafeOnPremConnectorState, opts ...pulumi.ResourceOption) (*DataSafeOnPremConnector, error) {
	var resource DataSafeOnPremConnector
	err := ctx.ReadResource("oci:index/dataSafeOnPremConnector:DataSafeOnPremConnector", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DataSafeOnPremConnector resources.
type dataSafeOnPremConnectorState struct {
	// Latest available version of the on-premises connector.
	AvailableVersion *string `pulumi:"availableVersion"`
	// (Updatable) The OCID of the compartment where you want to create the on-premises connector.
	CompartmentId *string `pulumi:"compartmentId"`
	// Created version of the on-premises connector.
	CreatedVersion *string `pulumi:"createdVersion"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description of the on-premises connector.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the on-premises connector. The name does not have to be unique, and it's changeable.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Details about the current state of the on-premises connector.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The current state of the on-premises connector.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The date and time the on-premises connector was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
}

type DataSafeOnPremConnectorState struct {
	// Latest available version of the on-premises connector.
	AvailableVersion pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment where you want to create the on-premises connector.
	CompartmentId pulumi.StringPtrInput
	// Created version of the on-premises connector.
	CreatedVersion pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description of the on-premises connector.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the on-premises connector. The name does not have to be unique, and it's changeable.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Details about the current state of the on-premises connector.
	LifecycleDetails pulumi.StringPtrInput
	// The current state of the on-premises connector.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The date and time the on-premises connector was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
}

func (DataSafeOnPremConnectorState) ElementType() reflect.Type {
	return reflect.TypeOf((*dataSafeOnPremConnectorState)(nil)).Elem()
}

type dataSafeOnPremConnectorArgs struct {
	// (Updatable) The OCID of the compartment where you want to create the on-premises connector.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description of the on-premises connector.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the on-premises connector. The name does not have to be unique, and it's changeable.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
}

// The set of arguments for constructing a DataSafeOnPremConnector resource.
type DataSafeOnPremConnectorArgs struct {
	// (Updatable) The OCID of the compartment where you want to create the on-premises connector.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description of the on-premises connector.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the on-premises connector. The name does not have to be unique, and it's changeable.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
}

func (DataSafeOnPremConnectorArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*dataSafeOnPremConnectorArgs)(nil)).Elem()
}

type DataSafeOnPremConnectorInput interface {
	pulumi.Input

	ToDataSafeOnPremConnectorOutput() DataSafeOnPremConnectorOutput
	ToDataSafeOnPremConnectorOutputWithContext(ctx context.Context) DataSafeOnPremConnectorOutput
}

func (*DataSafeOnPremConnector) ElementType() reflect.Type {
	return reflect.TypeOf((*DataSafeOnPremConnector)(nil))
}

func (i *DataSafeOnPremConnector) ToDataSafeOnPremConnectorOutput() DataSafeOnPremConnectorOutput {
	return i.ToDataSafeOnPremConnectorOutputWithContext(context.Background())
}

func (i *DataSafeOnPremConnector) ToDataSafeOnPremConnectorOutputWithContext(ctx context.Context) DataSafeOnPremConnectorOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataSafeOnPremConnectorOutput)
}

func (i *DataSafeOnPremConnector) ToDataSafeOnPremConnectorPtrOutput() DataSafeOnPremConnectorPtrOutput {
	return i.ToDataSafeOnPremConnectorPtrOutputWithContext(context.Background())
}

func (i *DataSafeOnPremConnector) ToDataSafeOnPremConnectorPtrOutputWithContext(ctx context.Context) DataSafeOnPremConnectorPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataSafeOnPremConnectorPtrOutput)
}

type DataSafeOnPremConnectorPtrInput interface {
	pulumi.Input

	ToDataSafeOnPremConnectorPtrOutput() DataSafeOnPremConnectorPtrOutput
	ToDataSafeOnPremConnectorPtrOutputWithContext(ctx context.Context) DataSafeOnPremConnectorPtrOutput
}

type dataSafeOnPremConnectorPtrType DataSafeOnPremConnectorArgs

func (*dataSafeOnPremConnectorPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**DataSafeOnPremConnector)(nil))
}

func (i *dataSafeOnPremConnectorPtrType) ToDataSafeOnPremConnectorPtrOutput() DataSafeOnPremConnectorPtrOutput {
	return i.ToDataSafeOnPremConnectorPtrOutputWithContext(context.Background())
}

func (i *dataSafeOnPremConnectorPtrType) ToDataSafeOnPremConnectorPtrOutputWithContext(ctx context.Context) DataSafeOnPremConnectorPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataSafeOnPremConnectorPtrOutput)
}

// DataSafeOnPremConnectorArrayInput is an input type that accepts DataSafeOnPremConnectorArray and DataSafeOnPremConnectorArrayOutput values.
// You can construct a concrete instance of `DataSafeOnPremConnectorArrayInput` via:
//
//          DataSafeOnPremConnectorArray{ DataSafeOnPremConnectorArgs{...} }
type DataSafeOnPremConnectorArrayInput interface {
	pulumi.Input

	ToDataSafeOnPremConnectorArrayOutput() DataSafeOnPremConnectorArrayOutput
	ToDataSafeOnPremConnectorArrayOutputWithContext(context.Context) DataSafeOnPremConnectorArrayOutput
}

type DataSafeOnPremConnectorArray []DataSafeOnPremConnectorInput

func (DataSafeOnPremConnectorArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DataSafeOnPremConnector)(nil)).Elem()
}

func (i DataSafeOnPremConnectorArray) ToDataSafeOnPremConnectorArrayOutput() DataSafeOnPremConnectorArrayOutput {
	return i.ToDataSafeOnPremConnectorArrayOutputWithContext(context.Background())
}

func (i DataSafeOnPremConnectorArray) ToDataSafeOnPremConnectorArrayOutputWithContext(ctx context.Context) DataSafeOnPremConnectorArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataSafeOnPremConnectorArrayOutput)
}

// DataSafeOnPremConnectorMapInput is an input type that accepts DataSafeOnPremConnectorMap and DataSafeOnPremConnectorMapOutput values.
// You can construct a concrete instance of `DataSafeOnPremConnectorMapInput` via:
//
//          DataSafeOnPremConnectorMap{ "key": DataSafeOnPremConnectorArgs{...} }
type DataSafeOnPremConnectorMapInput interface {
	pulumi.Input

	ToDataSafeOnPremConnectorMapOutput() DataSafeOnPremConnectorMapOutput
	ToDataSafeOnPremConnectorMapOutputWithContext(context.Context) DataSafeOnPremConnectorMapOutput
}

type DataSafeOnPremConnectorMap map[string]DataSafeOnPremConnectorInput

func (DataSafeOnPremConnectorMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DataSafeOnPremConnector)(nil)).Elem()
}

func (i DataSafeOnPremConnectorMap) ToDataSafeOnPremConnectorMapOutput() DataSafeOnPremConnectorMapOutput {
	return i.ToDataSafeOnPremConnectorMapOutputWithContext(context.Background())
}

func (i DataSafeOnPremConnectorMap) ToDataSafeOnPremConnectorMapOutputWithContext(ctx context.Context) DataSafeOnPremConnectorMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataSafeOnPremConnectorMapOutput)
}

type DataSafeOnPremConnectorOutput struct {
	*pulumi.OutputState
}

func (DataSafeOnPremConnectorOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*DataSafeOnPremConnector)(nil))
}

func (o DataSafeOnPremConnectorOutput) ToDataSafeOnPremConnectorOutput() DataSafeOnPremConnectorOutput {
	return o
}

func (o DataSafeOnPremConnectorOutput) ToDataSafeOnPremConnectorOutputWithContext(ctx context.Context) DataSafeOnPremConnectorOutput {
	return o
}

func (o DataSafeOnPremConnectorOutput) ToDataSafeOnPremConnectorPtrOutput() DataSafeOnPremConnectorPtrOutput {
	return o.ToDataSafeOnPremConnectorPtrOutputWithContext(context.Background())
}

func (o DataSafeOnPremConnectorOutput) ToDataSafeOnPremConnectorPtrOutputWithContext(ctx context.Context) DataSafeOnPremConnectorPtrOutput {
	return o.ApplyT(func(v DataSafeOnPremConnector) *DataSafeOnPremConnector {
		return &v
	}).(DataSafeOnPremConnectorPtrOutput)
}

type DataSafeOnPremConnectorPtrOutput struct {
	*pulumi.OutputState
}

func (DataSafeOnPremConnectorPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DataSafeOnPremConnector)(nil))
}

func (o DataSafeOnPremConnectorPtrOutput) ToDataSafeOnPremConnectorPtrOutput() DataSafeOnPremConnectorPtrOutput {
	return o
}

func (o DataSafeOnPremConnectorPtrOutput) ToDataSafeOnPremConnectorPtrOutputWithContext(ctx context.Context) DataSafeOnPremConnectorPtrOutput {
	return o
}

type DataSafeOnPremConnectorArrayOutput struct{ *pulumi.OutputState }

func (DataSafeOnPremConnectorArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]DataSafeOnPremConnector)(nil))
}

func (o DataSafeOnPremConnectorArrayOutput) ToDataSafeOnPremConnectorArrayOutput() DataSafeOnPremConnectorArrayOutput {
	return o
}

func (o DataSafeOnPremConnectorArrayOutput) ToDataSafeOnPremConnectorArrayOutputWithContext(ctx context.Context) DataSafeOnPremConnectorArrayOutput {
	return o
}

func (o DataSafeOnPremConnectorArrayOutput) Index(i pulumi.IntInput) DataSafeOnPremConnectorOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) DataSafeOnPremConnector {
		return vs[0].([]DataSafeOnPremConnector)[vs[1].(int)]
	}).(DataSafeOnPremConnectorOutput)
}

type DataSafeOnPremConnectorMapOutput struct{ *pulumi.OutputState }

func (DataSafeOnPremConnectorMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]DataSafeOnPremConnector)(nil))
}

func (o DataSafeOnPremConnectorMapOutput) ToDataSafeOnPremConnectorMapOutput() DataSafeOnPremConnectorMapOutput {
	return o
}

func (o DataSafeOnPremConnectorMapOutput) ToDataSafeOnPremConnectorMapOutputWithContext(ctx context.Context) DataSafeOnPremConnectorMapOutput {
	return o
}

func (o DataSafeOnPremConnectorMapOutput) MapIndex(k pulumi.StringInput) DataSafeOnPremConnectorOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) DataSafeOnPremConnector {
		return vs[0].(map[string]DataSafeOnPremConnector)[vs[1].(string)]
	}).(DataSafeOnPremConnectorOutput)
}

func init() {
	pulumi.RegisterOutputType(DataSafeOnPremConnectorOutput{})
	pulumi.RegisterOutputType(DataSafeOnPremConnectorPtrOutput{})
	pulumi.RegisterOutputType(DataSafeOnPremConnectorArrayOutput{})
	pulumi.RegisterOutputType(DataSafeOnPremConnectorMapOutput{})
}
