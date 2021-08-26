// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package budget

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Budget resource in Oracle Cloud Infrastructure Budget service.
//
// Creates a new Budget.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/budget"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := budget.NewBudget(ctx, "testBudget", &budget.BudgetArgs{
// 			Amount:                            pulumi.Any(_var.Budget_amount),
// 			CompartmentId:                     pulumi.Any(_var.Tenancy_ocid),
// 			ResetPeriod:                       pulumi.Any(_var.Budget_reset_period),
// 			BudgetProcessingPeriodStartOffset: pulumi.Any(_var.Budget_budget_processing_period_start_offset),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			Description: pulumi.Any(_var.Budget_description),
// 			DisplayName: pulumi.Any(_var.Budget_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
// 			TargetCompartmentId: pulumi.Any(oci_identity_compartment.Test_compartment.Id),
// 			TargetType:          pulumi.Any(_var.Budget_target_type),
// 			Targets:             pulumi.Any(_var.Budget_targets),
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
// Budgets can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:budget/budget:Budget test_budget "id"
// ```
type Budget struct {
	pulumi.CustomResourceState

	// The actual spend in currency for the current budget cycle
	ActualSpend pulumi.Float64Output `pulumi:"actualSpend"`
	// Total number of alert rules in the budget
	AlertRuleCount pulumi.IntOutput `pulumi:"alertRuleCount"`
	// (Updatable) The amount of the budget expressed as a whole number in the currency of the customer's rate card.
	Amount pulumi.IntOutput `pulumi:"amount"`
	// (Updatable) The number of days offset from the first day of the month, at which the budget processing period starts. In months that have fewer days than this value, processing will begin on the last day of that month. For example, for a value of 12, processing starts every month on the 12th at midnight.
	BudgetProcessingPeriodStartOffset pulumi.IntOutput `pulumi:"budgetProcessingPeriodStartOffset"`
	// The OCID of the tenancy
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) The description of the budget.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The displayName of the budget.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The forecasted spend in currency by the end of the current budget cycle
	ForecastedSpend pulumi.Float64Output `pulumi:"forecastedSpend"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// (Updatable) The reset period for the budget. Valid value is MONTHLY.
	ResetPeriod pulumi.StringOutput `pulumi:"resetPeriod"`
	// The current state of the budget.
	State pulumi.StringOutput `pulumi:"state"`
	// This is DEPRECTAED. Set the target compartment id in targets instead.
	//
	// Deprecated: The 'target_compartment_id' field has been deprecated. Please use 'target_type' instead.
	TargetCompartmentId pulumi.StringOutput `pulumi:"targetCompartmentId"`
	// The type of target on which the budget is applied.
	TargetType pulumi.StringOutput `pulumi:"targetType"`
	// The list of targets on which the budget is applied. If targetType is "COMPARTMENT", targets contains list of compartment OCIDs. If targetType is "TAG", targets contains list of cost tracking tag identifiers in the form of "{tagNamespace}.{tagKey}.{tagValue}". Curerntly, the array should contain EXACT ONE item.
	Targets pulumi.StringArrayOutput `pulumi:"targets"`
	// Time that budget was created
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time that the budget spend was last computed
	TimeSpendComputed pulumi.StringOutput `pulumi:"timeSpendComputed"`
	// Time that budget was updated
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// Version of the budget. Starts from 1 and increments by 1.
	Version pulumi.IntOutput `pulumi:"version"`
}

// NewBudget registers a new resource with the given unique name, arguments, and options.
func NewBudget(ctx *pulumi.Context,
	name string, args *BudgetArgs, opts ...pulumi.ResourceOption) (*Budget, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Amount == nil {
		return nil, errors.New("invalid value for required argument 'Amount'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.ResetPeriod == nil {
		return nil, errors.New("invalid value for required argument 'ResetPeriod'")
	}
	var resource Budget
	err := ctx.RegisterResource("oci:budget/budget:Budget", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetBudget gets an existing Budget resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetBudget(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *BudgetState, opts ...pulumi.ResourceOption) (*Budget, error) {
	var resource Budget
	err := ctx.ReadResource("oci:budget/budget:Budget", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Budget resources.
type budgetState struct {
	// The actual spend in currency for the current budget cycle
	ActualSpend *float64 `pulumi:"actualSpend"`
	// Total number of alert rules in the budget
	AlertRuleCount *int `pulumi:"alertRuleCount"`
	// (Updatable) The amount of the budget expressed as a whole number in the currency of the customer's rate card.
	Amount *int `pulumi:"amount"`
	// (Updatable) The number of days offset from the first day of the month, at which the budget processing period starts. In months that have fewer days than this value, processing will begin on the last day of that month. For example, for a value of 12, processing starts every month on the 12th at midnight.
	BudgetProcessingPeriodStartOffset *int `pulumi:"budgetProcessingPeriodStartOffset"`
	// The OCID of the tenancy
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description of the budget.
	Description *string `pulumi:"description"`
	// (Updatable) The displayName of the budget.
	DisplayName *string `pulumi:"displayName"`
	// The forecasted spend in currency by the end of the current budget cycle
	ForecastedSpend *float64 `pulumi:"forecastedSpend"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The reset period for the budget. Valid value is MONTHLY.
	ResetPeriod *string `pulumi:"resetPeriod"`
	// The current state of the budget.
	State *string `pulumi:"state"`
	// This is DEPRECTAED. Set the target compartment id in targets instead.
	//
	// Deprecated: The 'target_compartment_id' field has been deprecated. Please use 'target_type' instead.
	TargetCompartmentId *string `pulumi:"targetCompartmentId"`
	// The type of target on which the budget is applied.
	TargetType *string `pulumi:"targetType"`
	// The list of targets on which the budget is applied. If targetType is "COMPARTMENT", targets contains list of compartment OCIDs. If targetType is "TAG", targets contains list of cost tracking tag identifiers in the form of "{tagNamespace}.{tagKey}.{tagValue}". Curerntly, the array should contain EXACT ONE item.
	Targets []string `pulumi:"targets"`
	// Time that budget was created
	TimeCreated *string `pulumi:"timeCreated"`
	// The time that the budget spend was last computed
	TimeSpendComputed *string `pulumi:"timeSpendComputed"`
	// Time that budget was updated
	TimeUpdated *string `pulumi:"timeUpdated"`
	// Version of the budget. Starts from 1 and increments by 1.
	Version *int `pulumi:"version"`
}

type BudgetState struct {
	// The actual spend in currency for the current budget cycle
	ActualSpend pulumi.Float64PtrInput
	// Total number of alert rules in the budget
	AlertRuleCount pulumi.IntPtrInput
	// (Updatable) The amount of the budget expressed as a whole number in the currency of the customer's rate card.
	Amount pulumi.IntPtrInput
	// (Updatable) The number of days offset from the first day of the month, at which the budget processing period starts. In months that have fewer days than this value, processing will begin on the last day of that month. For example, for a value of 12, processing starts every month on the 12th at midnight.
	BudgetProcessingPeriodStartOffset pulumi.IntPtrInput
	// The OCID of the tenancy
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description of the budget.
	Description pulumi.StringPtrInput
	// (Updatable) The displayName of the budget.
	DisplayName pulumi.StringPtrInput
	// The forecasted spend in currency by the end of the current budget cycle
	ForecastedSpend pulumi.Float64PtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The reset period for the budget. Valid value is MONTHLY.
	ResetPeriod pulumi.StringPtrInput
	// The current state of the budget.
	State pulumi.StringPtrInput
	// This is DEPRECTAED. Set the target compartment id in targets instead.
	//
	// Deprecated: The 'target_compartment_id' field has been deprecated. Please use 'target_type' instead.
	TargetCompartmentId pulumi.StringPtrInput
	// The type of target on which the budget is applied.
	TargetType pulumi.StringPtrInput
	// The list of targets on which the budget is applied. If targetType is "COMPARTMENT", targets contains list of compartment OCIDs. If targetType is "TAG", targets contains list of cost tracking tag identifiers in the form of "{tagNamespace}.{tagKey}.{tagValue}". Curerntly, the array should contain EXACT ONE item.
	Targets pulumi.StringArrayInput
	// Time that budget was created
	TimeCreated pulumi.StringPtrInput
	// The time that the budget spend was last computed
	TimeSpendComputed pulumi.StringPtrInput
	// Time that budget was updated
	TimeUpdated pulumi.StringPtrInput
	// Version of the budget. Starts from 1 and increments by 1.
	Version pulumi.IntPtrInput
}

func (BudgetState) ElementType() reflect.Type {
	return reflect.TypeOf((*budgetState)(nil)).Elem()
}

type budgetArgs struct {
	// (Updatable) The amount of the budget expressed as a whole number in the currency of the customer's rate card.
	Amount int `pulumi:"amount"`
	// (Updatable) The number of days offset from the first day of the month, at which the budget processing period starts. In months that have fewer days than this value, processing will begin on the last day of that month. For example, for a value of 12, processing starts every month on the 12th at midnight.
	BudgetProcessingPeriodStartOffset *int `pulumi:"budgetProcessingPeriodStartOffset"`
	// The OCID of the tenancy
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description of the budget.
	Description *string `pulumi:"description"`
	// (Updatable) The displayName of the budget.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The reset period for the budget. Valid value is MONTHLY.
	ResetPeriod string `pulumi:"resetPeriod"`
	// This is DEPRECTAED. Set the target compartment id in targets instead.
	//
	// Deprecated: The 'target_compartment_id' field has been deprecated. Please use 'target_type' instead.
	TargetCompartmentId *string `pulumi:"targetCompartmentId"`
	// The type of target on which the budget is applied.
	TargetType *string `pulumi:"targetType"`
	// The list of targets on which the budget is applied. If targetType is "COMPARTMENT", targets contains list of compartment OCIDs. If targetType is "TAG", targets contains list of cost tracking tag identifiers in the form of "{tagNamespace}.{tagKey}.{tagValue}". Curerntly, the array should contain EXACT ONE item.
	Targets []string `pulumi:"targets"`
}

// The set of arguments for constructing a Budget resource.
type BudgetArgs struct {
	// (Updatable) The amount of the budget expressed as a whole number in the currency of the customer's rate card.
	Amount pulumi.IntInput
	// (Updatable) The number of days offset from the first day of the month, at which the budget processing period starts. In months that have fewer days than this value, processing will begin on the last day of that month. For example, for a value of 12, processing starts every month on the 12th at midnight.
	BudgetProcessingPeriodStartOffset pulumi.IntPtrInput
	// The OCID of the tenancy
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description of the budget.
	Description pulumi.StringPtrInput
	// (Updatable) The displayName of the budget.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The reset period for the budget. Valid value is MONTHLY.
	ResetPeriod pulumi.StringInput
	// This is DEPRECTAED. Set the target compartment id in targets instead.
	//
	// Deprecated: The 'target_compartment_id' field has been deprecated. Please use 'target_type' instead.
	TargetCompartmentId pulumi.StringPtrInput
	// The type of target on which the budget is applied.
	TargetType pulumi.StringPtrInput
	// The list of targets on which the budget is applied. If targetType is "COMPARTMENT", targets contains list of compartment OCIDs. If targetType is "TAG", targets contains list of cost tracking tag identifiers in the form of "{tagNamespace}.{tagKey}.{tagValue}". Curerntly, the array should contain EXACT ONE item.
	Targets pulumi.StringArrayInput
}

func (BudgetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*budgetArgs)(nil)).Elem()
}

type BudgetInput interface {
	pulumi.Input

	ToBudgetOutput() BudgetOutput
	ToBudgetOutputWithContext(ctx context.Context) BudgetOutput
}

func (*Budget) ElementType() reflect.Type {
	return reflect.TypeOf((*Budget)(nil))
}

func (i *Budget) ToBudgetOutput() BudgetOutput {
	return i.ToBudgetOutputWithContext(context.Background())
}

func (i *Budget) ToBudgetOutputWithContext(ctx context.Context) BudgetOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BudgetOutput)
}

func (i *Budget) ToBudgetPtrOutput() BudgetPtrOutput {
	return i.ToBudgetPtrOutputWithContext(context.Background())
}

func (i *Budget) ToBudgetPtrOutputWithContext(ctx context.Context) BudgetPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BudgetPtrOutput)
}

type BudgetPtrInput interface {
	pulumi.Input

	ToBudgetPtrOutput() BudgetPtrOutput
	ToBudgetPtrOutputWithContext(ctx context.Context) BudgetPtrOutput
}

type budgetPtrType BudgetArgs

func (*budgetPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**Budget)(nil))
}

func (i *budgetPtrType) ToBudgetPtrOutput() BudgetPtrOutput {
	return i.ToBudgetPtrOutputWithContext(context.Background())
}

func (i *budgetPtrType) ToBudgetPtrOutputWithContext(ctx context.Context) BudgetPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BudgetPtrOutput)
}

// BudgetArrayInput is an input type that accepts BudgetArray and BudgetArrayOutput values.
// You can construct a concrete instance of `BudgetArrayInput` via:
//
//          BudgetArray{ BudgetArgs{...} }
type BudgetArrayInput interface {
	pulumi.Input

	ToBudgetArrayOutput() BudgetArrayOutput
	ToBudgetArrayOutputWithContext(context.Context) BudgetArrayOutput
}

type BudgetArray []BudgetInput

func (BudgetArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Budget)(nil)).Elem()
}

func (i BudgetArray) ToBudgetArrayOutput() BudgetArrayOutput {
	return i.ToBudgetArrayOutputWithContext(context.Background())
}

func (i BudgetArray) ToBudgetArrayOutputWithContext(ctx context.Context) BudgetArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BudgetArrayOutput)
}

// BudgetMapInput is an input type that accepts BudgetMap and BudgetMapOutput values.
// You can construct a concrete instance of `BudgetMapInput` via:
//
//          BudgetMap{ "key": BudgetArgs{...} }
type BudgetMapInput interface {
	pulumi.Input

	ToBudgetMapOutput() BudgetMapOutput
	ToBudgetMapOutputWithContext(context.Context) BudgetMapOutput
}

type BudgetMap map[string]BudgetInput

func (BudgetMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Budget)(nil)).Elem()
}

func (i BudgetMap) ToBudgetMapOutput() BudgetMapOutput {
	return i.ToBudgetMapOutputWithContext(context.Background())
}

func (i BudgetMap) ToBudgetMapOutputWithContext(ctx context.Context) BudgetMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BudgetMapOutput)
}

type BudgetOutput struct {
	*pulumi.OutputState
}

func (BudgetOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*Budget)(nil))
}

func (o BudgetOutput) ToBudgetOutput() BudgetOutput {
	return o
}

func (o BudgetOutput) ToBudgetOutputWithContext(ctx context.Context) BudgetOutput {
	return o
}

func (o BudgetOutput) ToBudgetPtrOutput() BudgetPtrOutput {
	return o.ToBudgetPtrOutputWithContext(context.Background())
}

func (o BudgetOutput) ToBudgetPtrOutputWithContext(ctx context.Context) BudgetPtrOutput {
	return o.ApplyT(func(v Budget) *Budget {
		return &v
	}).(BudgetPtrOutput)
}

type BudgetPtrOutput struct {
	*pulumi.OutputState
}

func (BudgetPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Budget)(nil))
}

func (o BudgetPtrOutput) ToBudgetPtrOutput() BudgetPtrOutput {
	return o
}

func (o BudgetPtrOutput) ToBudgetPtrOutputWithContext(ctx context.Context) BudgetPtrOutput {
	return o
}

type BudgetArrayOutput struct{ *pulumi.OutputState }

func (BudgetArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]Budget)(nil))
}

func (o BudgetArrayOutput) ToBudgetArrayOutput() BudgetArrayOutput {
	return o
}

func (o BudgetArrayOutput) ToBudgetArrayOutputWithContext(ctx context.Context) BudgetArrayOutput {
	return o
}

func (o BudgetArrayOutput) Index(i pulumi.IntInput) BudgetOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) Budget {
		return vs[0].([]Budget)[vs[1].(int)]
	}).(BudgetOutput)
}

type BudgetMapOutput struct{ *pulumi.OutputState }

func (BudgetMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]Budget)(nil))
}

func (o BudgetMapOutput) ToBudgetMapOutput() BudgetMapOutput {
	return o
}

func (o BudgetMapOutput) ToBudgetMapOutputWithContext(ctx context.Context) BudgetMapOutput {
	return o
}

func (o BudgetMapOutput) MapIndex(k pulumi.StringInput) BudgetOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) Budget {
		return vs[0].(map[string]Budget)[vs[1].(string)]
	}).(BudgetOutput)
}

func init() {
	pulumi.RegisterOutputType(BudgetOutput{})
	pulumi.RegisterOutputType(BudgetPtrOutput{})
	pulumi.RegisterOutputType(BudgetArrayOutput{})
	pulumi.RegisterOutputType(BudgetMapOutput{})
}
