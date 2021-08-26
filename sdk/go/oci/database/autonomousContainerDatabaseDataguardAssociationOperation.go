// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Autonomous Container Database Dataguard Association Operation resource in Oracle Cloud Infrastructure Database service.
//
// Perform a new Autonomous Container Database Dataguard Association Operation on an Autonomous Container Database that has Dataguard enabled
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/database"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := database.NewAutonomousContainerDatabaseDataguardAssociationOperation(ctx, "switchover", &database.AutonomousContainerDatabaseDataguardAssociationOperationArgs{
// 			Operation:                     pulumi.String("switchover"),
// 			AutonomousContainerDatabaseId: pulumi.Any(data.Oci_database_autonomous_container_database_dataguard_associations.Dataguard_associations.Autonomous_container_database_dataguard_associations[0].Autonomous_container_database_id),
// 			AutonomousContainerDatabaseDataguardAssociationId: pulumi.Any(data.Oci_database_autonomous_container_database_dataguard_associations.Dataguard_associations.Autonomous_container_database_dataguard_associations[0].Id),
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
// AutonomousContainerDatabaseDataguardAssociationOperation does not support import.
type AutonomousContainerDatabaseDataguardAssociationOperation struct {
	pulumi.CustomResourceState

	// The Autonomous Container Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
	AutonomousContainerDatabaseDataguardAssociationId pulumi.StringOutput `pulumi:"autonomousContainerDatabaseDataguardAssociationId"`
	// The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
	AutonomousContainerDatabaseId pulumi.StringOutput `pulumi:"autonomousContainerDatabaseId"`
	// There are three type of supported operations `switchover`, `failover`, `reinstate`. `switchover` can only be used for primary database while `failover` and `reinstate` can only be used for standby database. This attribute is a forcenew attribute.
	Operation pulumi.StringOutput `pulumi:"operation"`
}

// NewAutonomousContainerDatabaseDataguardAssociationOperation registers a new resource with the given unique name, arguments, and options.
func NewAutonomousContainerDatabaseDataguardAssociationOperation(ctx *pulumi.Context,
	name string, args *AutonomousContainerDatabaseDataguardAssociationOperationArgs, opts ...pulumi.ResourceOption) (*AutonomousContainerDatabaseDataguardAssociationOperation, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AutonomousContainerDatabaseDataguardAssociationId == nil {
		return nil, errors.New("invalid value for required argument 'AutonomousContainerDatabaseDataguardAssociationId'")
	}
	if args.AutonomousContainerDatabaseId == nil {
		return nil, errors.New("invalid value for required argument 'AutonomousContainerDatabaseId'")
	}
	if args.Operation == nil {
		return nil, errors.New("invalid value for required argument 'Operation'")
	}
	var resource AutonomousContainerDatabaseDataguardAssociationOperation
	err := ctx.RegisterResource("oci:database/autonomousContainerDatabaseDataguardAssociationOperation:AutonomousContainerDatabaseDataguardAssociationOperation", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAutonomousContainerDatabaseDataguardAssociationOperation gets an existing AutonomousContainerDatabaseDataguardAssociationOperation resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAutonomousContainerDatabaseDataguardAssociationOperation(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AutonomousContainerDatabaseDataguardAssociationOperationState, opts ...pulumi.ResourceOption) (*AutonomousContainerDatabaseDataguardAssociationOperation, error) {
	var resource AutonomousContainerDatabaseDataguardAssociationOperation
	err := ctx.ReadResource("oci:database/autonomousContainerDatabaseDataguardAssociationOperation:AutonomousContainerDatabaseDataguardAssociationOperation", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering AutonomousContainerDatabaseDataguardAssociationOperation resources.
type autonomousContainerDatabaseDataguardAssociationOperationState struct {
	// The Autonomous Container Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
	AutonomousContainerDatabaseDataguardAssociationId *string `pulumi:"autonomousContainerDatabaseDataguardAssociationId"`
	// The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
	AutonomousContainerDatabaseId *string `pulumi:"autonomousContainerDatabaseId"`
	// There are three type of supported operations `switchover`, `failover`, `reinstate`. `switchover` can only be used for primary database while `failover` and `reinstate` can only be used for standby database. This attribute is a forcenew attribute.
	Operation *string `pulumi:"operation"`
}

type AutonomousContainerDatabaseDataguardAssociationOperationState struct {
	// The Autonomous Container Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
	AutonomousContainerDatabaseDataguardAssociationId pulumi.StringPtrInput
	// The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
	AutonomousContainerDatabaseId pulumi.StringPtrInput
	// There are three type of supported operations `switchover`, `failover`, `reinstate`. `switchover` can only be used for primary database while `failover` and `reinstate` can only be used for standby database. This attribute is a forcenew attribute.
	Operation pulumi.StringPtrInput
}

func (AutonomousContainerDatabaseDataguardAssociationOperationState) ElementType() reflect.Type {
	return reflect.TypeOf((*autonomousContainerDatabaseDataguardAssociationOperationState)(nil)).Elem()
}

type autonomousContainerDatabaseDataguardAssociationOperationArgs struct {
	// The Autonomous Container Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
	AutonomousContainerDatabaseDataguardAssociationId string `pulumi:"autonomousContainerDatabaseDataguardAssociationId"`
	// The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
	AutonomousContainerDatabaseId string `pulumi:"autonomousContainerDatabaseId"`
	// There are three type of supported operations `switchover`, `failover`, `reinstate`. `switchover` can only be used for primary database while `failover` and `reinstate` can only be used for standby database. This attribute is a forcenew attribute.
	Operation string `pulumi:"operation"`
}

// The set of arguments for constructing a AutonomousContainerDatabaseDataguardAssociationOperation resource.
type AutonomousContainerDatabaseDataguardAssociationOperationArgs struct {
	// The Autonomous Container Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
	AutonomousContainerDatabaseDataguardAssociationId pulumi.StringInput
	// The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
	AutonomousContainerDatabaseId pulumi.StringInput
	// There are three type of supported operations `switchover`, `failover`, `reinstate`. `switchover` can only be used for primary database while `failover` and `reinstate` can only be used for standby database. This attribute is a forcenew attribute.
	Operation pulumi.StringInput
}

func (AutonomousContainerDatabaseDataguardAssociationOperationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*autonomousContainerDatabaseDataguardAssociationOperationArgs)(nil)).Elem()
}

type AutonomousContainerDatabaseDataguardAssociationOperationInput interface {
	pulumi.Input

	ToAutonomousContainerDatabaseDataguardAssociationOperationOutput() AutonomousContainerDatabaseDataguardAssociationOperationOutput
	ToAutonomousContainerDatabaseDataguardAssociationOperationOutputWithContext(ctx context.Context) AutonomousContainerDatabaseDataguardAssociationOperationOutput
}

func (*AutonomousContainerDatabaseDataguardAssociationOperation) ElementType() reflect.Type {
	return reflect.TypeOf((*AutonomousContainerDatabaseDataguardAssociationOperation)(nil))
}

func (i *AutonomousContainerDatabaseDataguardAssociationOperation) ToAutonomousContainerDatabaseDataguardAssociationOperationOutput() AutonomousContainerDatabaseDataguardAssociationOperationOutput {
	return i.ToAutonomousContainerDatabaseDataguardAssociationOperationOutputWithContext(context.Background())
}

func (i *AutonomousContainerDatabaseDataguardAssociationOperation) ToAutonomousContainerDatabaseDataguardAssociationOperationOutputWithContext(ctx context.Context) AutonomousContainerDatabaseDataguardAssociationOperationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutonomousContainerDatabaseDataguardAssociationOperationOutput)
}

func (i *AutonomousContainerDatabaseDataguardAssociationOperation) ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutput() AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput {
	return i.ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutputWithContext(context.Background())
}

func (i *AutonomousContainerDatabaseDataguardAssociationOperation) ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutputWithContext(ctx context.Context) AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput)
}

type AutonomousContainerDatabaseDataguardAssociationOperationPtrInput interface {
	pulumi.Input

	ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutput() AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput
	ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutputWithContext(ctx context.Context) AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput
}

type autonomousContainerDatabaseDataguardAssociationOperationPtrType AutonomousContainerDatabaseDataguardAssociationOperationArgs

func (*autonomousContainerDatabaseDataguardAssociationOperationPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**AutonomousContainerDatabaseDataguardAssociationOperation)(nil))
}

func (i *autonomousContainerDatabaseDataguardAssociationOperationPtrType) ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutput() AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput {
	return i.ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutputWithContext(context.Background())
}

func (i *autonomousContainerDatabaseDataguardAssociationOperationPtrType) ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutputWithContext(ctx context.Context) AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput)
}

// AutonomousContainerDatabaseDataguardAssociationOperationArrayInput is an input type that accepts AutonomousContainerDatabaseDataguardAssociationOperationArray and AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput values.
// You can construct a concrete instance of `AutonomousContainerDatabaseDataguardAssociationOperationArrayInput` via:
//
//          AutonomousContainerDatabaseDataguardAssociationOperationArray{ AutonomousContainerDatabaseDataguardAssociationOperationArgs{...} }
type AutonomousContainerDatabaseDataguardAssociationOperationArrayInput interface {
	pulumi.Input

	ToAutonomousContainerDatabaseDataguardAssociationOperationArrayOutput() AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput
	ToAutonomousContainerDatabaseDataguardAssociationOperationArrayOutputWithContext(context.Context) AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput
}

type AutonomousContainerDatabaseDataguardAssociationOperationArray []AutonomousContainerDatabaseDataguardAssociationOperationInput

func (AutonomousContainerDatabaseDataguardAssociationOperationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AutonomousContainerDatabaseDataguardAssociationOperation)(nil)).Elem()
}

func (i AutonomousContainerDatabaseDataguardAssociationOperationArray) ToAutonomousContainerDatabaseDataguardAssociationOperationArrayOutput() AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput {
	return i.ToAutonomousContainerDatabaseDataguardAssociationOperationArrayOutputWithContext(context.Background())
}

func (i AutonomousContainerDatabaseDataguardAssociationOperationArray) ToAutonomousContainerDatabaseDataguardAssociationOperationArrayOutputWithContext(ctx context.Context) AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput)
}

// AutonomousContainerDatabaseDataguardAssociationOperationMapInput is an input type that accepts AutonomousContainerDatabaseDataguardAssociationOperationMap and AutonomousContainerDatabaseDataguardAssociationOperationMapOutput values.
// You can construct a concrete instance of `AutonomousContainerDatabaseDataguardAssociationOperationMapInput` via:
//
//          AutonomousContainerDatabaseDataguardAssociationOperationMap{ "key": AutonomousContainerDatabaseDataguardAssociationOperationArgs{...} }
type AutonomousContainerDatabaseDataguardAssociationOperationMapInput interface {
	pulumi.Input

	ToAutonomousContainerDatabaseDataguardAssociationOperationMapOutput() AutonomousContainerDatabaseDataguardAssociationOperationMapOutput
	ToAutonomousContainerDatabaseDataguardAssociationOperationMapOutputWithContext(context.Context) AutonomousContainerDatabaseDataguardAssociationOperationMapOutput
}

type AutonomousContainerDatabaseDataguardAssociationOperationMap map[string]AutonomousContainerDatabaseDataguardAssociationOperationInput

func (AutonomousContainerDatabaseDataguardAssociationOperationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AutonomousContainerDatabaseDataguardAssociationOperation)(nil)).Elem()
}

func (i AutonomousContainerDatabaseDataguardAssociationOperationMap) ToAutonomousContainerDatabaseDataguardAssociationOperationMapOutput() AutonomousContainerDatabaseDataguardAssociationOperationMapOutput {
	return i.ToAutonomousContainerDatabaseDataguardAssociationOperationMapOutputWithContext(context.Background())
}

func (i AutonomousContainerDatabaseDataguardAssociationOperationMap) ToAutonomousContainerDatabaseDataguardAssociationOperationMapOutputWithContext(ctx context.Context) AutonomousContainerDatabaseDataguardAssociationOperationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AutonomousContainerDatabaseDataguardAssociationOperationMapOutput)
}

type AutonomousContainerDatabaseDataguardAssociationOperationOutput struct {
	*pulumi.OutputState
}

func (AutonomousContainerDatabaseDataguardAssociationOperationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*AutonomousContainerDatabaseDataguardAssociationOperation)(nil))
}

func (o AutonomousContainerDatabaseDataguardAssociationOperationOutput) ToAutonomousContainerDatabaseDataguardAssociationOperationOutput() AutonomousContainerDatabaseDataguardAssociationOperationOutput {
	return o
}

func (o AutonomousContainerDatabaseDataguardAssociationOperationOutput) ToAutonomousContainerDatabaseDataguardAssociationOperationOutputWithContext(ctx context.Context) AutonomousContainerDatabaseDataguardAssociationOperationOutput {
	return o
}

func (o AutonomousContainerDatabaseDataguardAssociationOperationOutput) ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutput() AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput {
	return o.ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutputWithContext(context.Background())
}

func (o AutonomousContainerDatabaseDataguardAssociationOperationOutput) ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutputWithContext(ctx context.Context) AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput {
	return o.ApplyT(func(v AutonomousContainerDatabaseDataguardAssociationOperation) *AutonomousContainerDatabaseDataguardAssociationOperation {
		return &v
	}).(AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput)
}

type AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput struct {
	*pulumi.OutputState
}

func (AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**AutonomousContainerDatabaseDataguardAssociationOperation)(nil))
}

func (o AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput) ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutput() AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput {
	return o
}

func (o AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput) ToAutonomousContainerDatabaseDataguardAssociationOperationPtrOutputWithContext(ctx context.Context) AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput {
	return o
}

type AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput struct{ *pulumi.OutputState }

func (AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]AutonomousContainerDatabaseDataguardAssociationOperation)(nil))
}

func (o AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput) ToAutonomousContainerDatabaseDataguardAssociationOperationArrayOutput() AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput {
	return o
}

func (o AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput) ToAutonomousContainerDatabaseDataguardAssociationOperationArrayOutputWithContext(ctx context.Context) AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput {
	return o
}

func (o AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput) Index(i pulumi.IntInput) AutonomousContainerDatabaseDataguardAssociationOperationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) AutonomousContainerDatabaseDataguardAssociationOperation {
		return vs[0].([]AutonomousContainerDatabaseDataguardAssociationOperation)[vs[1].(int)]
	}).(AutonomousContainerDatabaseDataguardAssociationOperationOutput)
}

type AutonomousContainerDatabaseDataguardAssociationOperationMapOutput struct{ *pulumi.OutputState }

func (AutonomousContainerDatabaseDataguardAssociationOperationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]AutonomousContainerDatabaseDataguardAssociationOperation)(nil))
}

func (o AutonomousContainerDatabaseDataguardAssociationOperationMapOutput) ToAutonomousContainerDatabaseDataguardAssociationOperationMapOutput() AutonomousContainerDatabaseDataguardAssociationOperationMapOutput {
	return o
}

func (o AutonomousContainerDatabaseDataguardAssociationOperationMapOutput) ToAutonomousContainerDatabaseDataguardAssociationOperationMapOutputWithContext(ctx context.Context) AutonomousContainerDatabaseDataguardAssociationOperationMapOutput {
	return o
}

func (o AutonomousContainerDatabaseDataguardAssociationOperationMapOutput) MapIndex(k pulumi.StringInput) AutonomousContainerDatabaseDataguardAssociationOperationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) AutonomousContainerDatabaseDataguardAssociationOperation {
		return vs[0].(map[string]AutonomousContainerDatabaseDataguardAssociationOperation)[vs[1].(string)]
	}).(AutonomousContainerDatabaseDataguardAssociationOperationOutput)
}

func init() {
	pulumi.RegisterOutputType(AutonomousContainerDatabaseDataguardAssociationOperationOutput{})
	pulumi.RegisterOutputType(AutonomousContainerDatabaseDataguardAssociationOperationPtrOutput{})
	pulumi.RegisterOutputType(AutonomousContainerDatabaseDataguardAssociationOperationArrayOutput{})
	pulumi.RegisterOutputType(AutonomousContainerDatabaseDataguardAssociationOperationMapOutput{})
}
