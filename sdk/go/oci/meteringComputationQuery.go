// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Query resource in Oracle Cloud Infrastructure Metering Computation service.
//
// Returns the created query.
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
// 		_, err := oci.NewMeteringComputationQuery(ctx, "testQuery", &oci.MeteringComputationQueryArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			QueryDefinition: &MeteringComputationQueryQueryDefinitionArgs{
// 				CostAnalysisUi: &MeteringComputationQueryQueryDefinitionCostAnalysisUiArgs{
// 					Graph:             pulumi.Any(_var.Query_query_definition_cost_analysis_ui_graph),
// 					IsCumulativeGraph: pulumi.Any(_var.Query_query_definition_cost_analysis_ui_is_cumulative_graph),
// 				},
// 				DisplayName: pulumi.Any(_var.Query_query_definition_display_name),
// 				ReportQuery: &MeteringComputationQueryQueryDefinitionReportQueryArgs{
// 					Granularity:      pulumi.Any(_var.Query_query_definition_report_query_granularity),
// 					TenantId:         pulumi.Any(oci_metering_computation_tenant.Test_tenant.Id),
// 					CompartmentDepth: pulumi.Any(_var.Query_query_definition_report_query_compartment_depth),
// 					DateRangeName:    pulumi.Any(_var.Query_query_definition_report_query_date_range_name),
// 					Filter:           pulumi.Any(_var.Query_query_definition_report_query_filter),
// 					Forecast: &MeteringComputationQueryQueryDefinitionReportQueryForecastArgs{
// 						TimeForecastEnded:   pulumi.Any(_var.Query_query_definition_report_query_forecast_time_forecast_ended),
// 						ForecastType:        pulumi.Any(_var.Query_query_definition_report_query_forecast_forecast_type),
// 						TimeForecastStarted: pulumi.Any(_var.Query_query_definition_report_query_forecast_time_forecast_started),
// 					},
// 					GroupBies: pulumi.Any(_var.Query_query_definition_report_query_group_by),
// 					GroupByTags: MeteringComputationQueryQueryDefinitionReportQueryGroupByTagArray{
// 						&MeteringComputationQueryQueryDefinitionReportQueryGroupByTagArgs{
// 							Key:       pulumi.Any(_var.Query_query_definition_report_query_group_by_tag_key),
// 							Namespace: pulumi.Any(_var.Query_query_definition_report_query_group_by_tag_namespace),
// 							Value:     pulumi.Any(_var.Query_query_definition_report_query_group_by_tag_value),
// 						},
// 					},
// 					IsAggregateByTime: pulumi.Any(_var.Query_query_definition_report_query_is_aggregate_by_time),
// 					QueryType:         pulumi.Any(_var.Query_query_definition_report_query_query_type),
// 					TimeUsageEnded:    pulumi.Any(_var.Query_query_definition_report_query_time_usage_ended),
// 					TimeUsageStarted:  pulumi.Any(_var.Query_query_definition_report_query_time_usage_started),
// 				},
// 				Version: pulumi.Any(_var.Query_query_definition_version),
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
// Queries can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/meteringComputationQuery:MeteringComputationQuery test_query "id"
// ```
type MeteringComputationQuery struct {
	pulumi.CustomResourceState

	// The compartment OCID.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The common fields for queries.
	QueryDefinition MeteringComputationQueryQueryDefinitionOutput `pulumi:"queryDefinition"`
}

// NewMeteringComputationQuery registers a new resource with the given unique name, arguments, and options.
func NewMeteringComputationQuery(ctx *pulumi.Context,
	name string, args *MeteringComputationQueryArgs, opts ...pulumi.ResourceOption) (*MeteringComputationQuery, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.QueryDefinition == nil {
		return nil, errors.New("invalid value for required argument 'QueryDefinition'")
	}
	var resource MeteringComputationQuery
	err := ctx.RegisterResource("oci:index/meteringComputationQuery:MeteringComputationQuery", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetMeteringComputationQuery gets an existing MeteringComputationQuery resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetMeteringComputationQuery(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *MeteringComputationQueryState, opts ...pulumi.ResourceOption) (*MeteringComputationQuery, error) {
	var resource MeteringComputationQuery
	err := ctx.ReadResource("oci:index/meteringComputationQuery:MeteringComputationQuery", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering MeteringComputationQuery resources.
type meteringComputationQueryState struct {
	// The compartment OCID.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The common fields for queries.
	QueryDefinition *MeteringComputationQueryQueryDefinition `pulumi:"queryDefinition"`
}

type MeteringComputationQueryState struct {
	// The compartment OCID.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The common fields for queries.
	QueryDefinition MeteringComputationQueryQueryDefinitionPtrInput
}

func (MeteringComputationQueryState) ElementType() reflect.Type {
	return reflect.TypeOf((*meteringComputationQueryState)(nil)).Elem()
}

type meteringComputationQueryArgs struct {
	// The compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The common fields for queries.
	QueryDefinition MeteringComputationQueryQueryDefinition `pulumi:"queryDefinition"`
}

// The set of arguments for constructing a MeteringComputationQuery resource.
type MeteringComputationQueryArgs struct {
	// The compartment OCID.
	CompartmentId pulumi.StringInput
	// (Updatable) The common fields for queries.
	QueryDefinition MeteringComputationQueryQueryDefinitionInput
}

func (MeteringComputationQueryArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*meteringComputationQueryArgs)(nil)).Elem()
}

type MeteringComputationQueryInput interface {
	pulumi.Input

	ToMeteringComputationQueryOutput() MeteringComputationQueryOutput
	ToMeteringComputationQueryOutputWithContext(ctx context.Context) MeteringComputationQueryOutput
}

func (*MeteringComputationQuery) ElementType() reflect.Type {
	return reflect.TypeOf((*MeteringComputationQuery)(nil))
}

func (i *MeteringComputationQuery) ToMeteringComputationQueryOutput() MeteringComputationQueryOutput {
	return i.ToMeteringComputationQueryOutputWithContext(context.Background())
}

func (i *MeteringComputationQuery) ToMeteringComputationQueryOutputWithContext(ctx context.Context) MeteringComputationQueryOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MeteringComputationQueryOutput)
}

func (i *MeteringComputationQuery) ToMeteringComputationQueryPtrOutput() MeteringComputationQueryPtrOutput {
	return i.ToMeteringComputationQueryPtrOutputWithContext(context.Background())
}

func (i *MeteringComputationQuery) ToMeteringComputationQueryPtrOutputWithContext(ctx context.Context) MeteringComputationQueryPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MeteringComputationQueryPtrOutput)
}

type MeteringComputationQueryPtrInput interface {
	pulumi.Input

	ToMeteringComputationQueryPtrOutput() MeteringComputationQueryPtrOutput
	ToMeteringComputationQueryPtrOutputWithContext(ctx context.Context) MeteringComputationQueryPtrOutput
}

type meteringComputationQueryPtrType MeteringComputationQueryArgs

func (*meteringComputationQueryPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**MeteringComputationQuery)(nil))
}

func (i *meteringComputationQueryPtrType) ToMeteringComputationQueryPtrOutput() MeteringComputationQueryPtrOutput {
	return i.ToMeteringComputationQueryPtrOutputWithContext(context.Background())
}

func (i *meteringComputationQueryPtrType) ToMeteringComputationQueryPtrOutputWithContext(ctx context.Context) MeteringComputationQueryPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MeteringComputationQueryPtrOutput)
}

// MeteringComputationQueryArrayInput is an input type that accepts MeteringComputationQueryArray and MeteringComputationQueryArrayOutput values.
// You can construct a concrete instance of `MeteringComputationQueryArrayInput` via:
//
//          MeteringComputationQueryArray{ MeteringComputationQueryArgs{...} }
type MeteringComputationQueryArrayInput interface {
	pulumi.Input

	ToMeteringComputationQueryArrayOutput() MeteringComputationQueryArrayOutput
	ToMeteringComputationQueryArrayOutputWithContext(context.Context) MeteringComputationQueryArrayOutput
}

type MeteringComputationQueryArray []MeteringComputationQueryInput

func (MeteringComputationQueryArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MeteringComputationQuery)(nil)).Elem()
}

func (i MeteringComputationQueryArray) ToMeteringComputationQueryArrayOutput() MeteringComputationQueryArrayOutput {
	return i.ToMeteringComputationQueryArrayOutputWithContext(context.Background())
}

func (i MeteringComputationQueryArray) ToMeteringComputationQueryArrayOutputWithContext(ctx context.Context) MeteringComputationQueryArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MeteringComputationQueryArrayOutput)
}

// MeteringComputationQueryMapInput is an input type that accepts MeteringComputationQueryMap and MeteringComputationQueryMapOutput values.
// You can construct a concrete instance of `MeteringComputationQueryMapInput` via:
//
//          MeteringComputationQueryMap{ "key": MeteringComputationQueryArgs{...} }
type MeteringComputationQueryMapInput interface {
	pulumi.Input

	ToMeteringComputationQueryMapOutput() MeteringComputationQueryMapOutput
	ToMeteringComputationQueryMapOutputWithContext(context.Context) MeteringComputationQueryMapOutput
}

type MeteringComputationQueryMap map[string]MeteringComputationQueryInput

func (MeteringComputationQueryMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MeteringComputationQuery)(nil)).Elem()
}

func (i MeteringComputationQueryMap) ToMeteringComputationQueryMapOutput() MeteringComputationQueryMapOutput {
	return i.ToMeteringComputationQueryMapOutputWithContext(context.Background())
}

func (i MeteringComputationQueryMap) ToMeteringComputationQueryMapOutputWithContext(ctx context.Context) MeteringComputationQueryMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MeteringComputationQueryMapOutput)
}

type MeteringComputationQueryOutput struct {
	*pulumi.OutputState
}

func (MeteringComputationQueryOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*MeteringComputationQuery)(nil))
}

func (o MeteringComputationQueryOutput) ToMeteringComputationQueryOutput() MeteringComputationQueryOutput {
	return o
}

func (o MeteringComputationQueryOutput) ToMeteringComputationQueryOutputWithContext(ctx context.Context) MeteringComputationQueryOutput {
	return o
}

func (o MeteringComputationQueryOutput) ToMeteringComputationQueryPtrOutput() MeteringComputationQueryPtrOutput {
	return o.ToMeteringComputationQueryPtrOutputWithContext(context.Background())
}

func (o MeteringComputationQueryOutput) ToMeteringComputationQueryPtrOutputWithContext(ctx context.Context) MeteringComputationQueryPtrOutput {
	return o.ApplyT(func(v MeteringComputationQuery) *MeteringComputationQuery {
		return &v
	}).(MeteringComputationQueryPtrOutput)
}

type MeteringComputationQueryPtrOutput struct {
	*pulumi.OutputState
}

func (MeteringComputationQueryPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**MeteringComputationQuery)(nil))
}

func (o MeteringComputationQueryPtrOutput) ToMeteringComputationQueryPtrOutput() MeteringComputationQueryPtrOutput {
	return o
}

func (o MeteringComputationQueryPtrOutput) ToMeteringComputationQueryPtrOutputWithContext(ctx context.Context) MeteringComputationQueryPtrOutput {
	return o
}

type MeteringComputationQueryArrayOutput struct{ *pulumi.OutputState }

func (MeteringComputationQueryArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]MeteringComputationQuery)(nil))
}

func (o MeteringComputationQueryArrayOutput) ToMeteringComputationQueryArrayOutput() MeteringComputationQueryArrayOutput {
	return o
}

func (o MeteringComputationQueryArrayOutput) ToMeteringComputationQueryArrayOutputWithContext(ctx context.Context) MeteringComputationQueryArrayOutput {
	return o
}

func (o MeteringComputationQueryArrayOutput) Index(i pulumi.IntInput) MeteringComputationQueryOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) MeteringComputationQuery {
		return vs[0].([]MeteringComputationQuery)[vs[1].(int)]
	}).(MeteringComputationQueryOutput)
}

type MeteringComputationQueryMapOutput struct{ *pulumi.OutputState }

func (MeteringComputationQueryMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]MeteringComputationQuery)(nil))
}

func (o MeteringComputationQueryMapOutput) ToMeteringComputationQueryMapOutput() MeteringComputationQueryMapOutput {
	return o
}

func (o MeteringComputationQueryMapOutput) ToMeteringComputationQueryMapOutputWithContext(ctx context.Context) MeteringComputationQueryMapOutput {
	return o
}

func (o MeteringComputationQueryMapOutput) MapIndex(k pulumi.StringInput) MeteringComputationQueryOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) MeteringComputationQuery {
		return vs[0].(map[string]MeteringComputationQuery)[vs[1].(string)]
	}).(MeteringComputationQueryOutput)
}

func init() {
	pulumi.RegisterOutputType(MeteringComputationQueryOutput{})
	pulumi.RegisterOutputType(MeteringComputationQueryPtrOutput{})
	pulumi.RegisterOutputType(MeteringComputationQueryArrayOutput{})
	pulumi.RegisterOutputType(MeteringComputationQueryMapOutput{})
}
