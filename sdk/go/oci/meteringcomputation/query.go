// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package meteringcomputation

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
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/meteringcomputation"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := meteringcomputation.NewQuery(ctx, "testQuery", &meteringcomputation.QueryArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			QueryDefinition: &meteringcomputation.QueryQueryDefinitionArgs{
// 				CostAnalysisUi: &meteringcomputation.QueryQueryDefinitionCostAnalysisUiArgs{
// 					Graph:             pulumi.Any(_var.Query_query_definition_cost_analysis_ui_graph),
// 					IsCumulativeGraph: pulumi.Any(_var.Query_query_definition_cost_analysis_ui_is_cumulative_graph),
// 				},
// 				DisplayName: pulumi.Any(_var.Query_query_definition_display_name),
// 				ReportQuery: &meteringcomputation.QueryQueryDefinitionReportQueryArgs{
// 					Granularity:      pulumi.Any(_var.Query_query_definition_report_query_granularity),
// 					TenantId:         pulumi.Any(oci_metering_computation_tenant.Test_tenant.Id),
// 					CompartmentDepth: pulumi.Any(_var.Query_query_definition_report_query_compartment_depth),
// 					DateRangeName:    pulumi.Any(_var.Query_query_definition_report_query_date_range_name),
// 					Filter:           pulumi.Any(_var.Query_query_definition_report_query_filter),
// 					Forecast: &meteringcomputation.QueryQueryDefinitionReportQueryForecastArgs{
// 						TimeForecastEnded:   pulumi.Any(_var.Query_query_definition_report_query_forecast_time_forecast_ended),
// 						ForecastType:        pulumi.Any(_var.Query_query_definition_report_query_forecast_forecast_type),
// 						TimeForecastStarted: pulumi.Any(_var.Query_query_definition_report_query_forecast_time_forecast_started),
// 					},
// 					GroupBies: pulumi.Any(_var.Query_query_definition_report_query_group_by),
// 					GroupByTags: meteringcomputation.QueryQueryDefinitionReportQueryGroupByTagArray{
// 						&meteringcomputation.QueryQueryDefinitionReportQueryGroupByTagArgs{
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
//  $ pulumi import oci:meteringcomputation/query:Query test_query "id"
// ```
type Query struct {
	pulumi.CustomResourceState

	// The compartment OCID.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The common fields for queries.
	QueryDefinition QueryQueryDefinitionOutput `pulumi:"queryDefinition"`
}

// NewQuery registers a new resource with the given unique name, arguments, and options.
func NewQuery(ctx *pulumi.Context,
	name string, args *QueryArgs, opts ...pulumi.ResourceOption) (*Query, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.QueryDefinition == nil {
		return nil, errors.New("invalid value for required argument 'QueryDefinition'")
	}
	var resource Query
	err := ctx.RegisterResource("oci:meteringcomputation/query:Query", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetQuery gets an existing Query resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetQuery(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *QueryState, opts ...pulumi.ResourceOption) (*Query, error) {
	var resource Query
	err := ctx.ReadResource("oci:meteringcomputation/query:Query", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Query resources.
type queryState struct {
	// The compartment OCID.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The common fields for queries.
	QueryDefinition *QueryQueryDefinition `pulumi:"queryDefinition"`
}

type QueryState struct {
	// The compartment OCID.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The common fields for queries.
	QueryDefinition QueryQueryDefinitionPtrInput
}

func (QueryState) ElementType() reflect.Type {
	return reflect.TypeOf((*queryState)(nil)).Elem()
}

type queryArgs struct {
	// The compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The common fields for queries.
	QueryDefinition QueryQueryDefinition `pulumi:"queryDefinition"`
}

// The set of arguments for constructing a Query resource.
type QueryArgs struct {
	// The compartment OCID.
	CompartmentId pulumi.StringInput
	// (Updatable) The common fields for queries.
	QueryDefinition QueryQueryDefinitionInput
}

func (QueryArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*queryArgs)(nil)).Elem()
}

type QueryInput interface {
	pulumi.Input

	ToQueryOutput() QueryOutput
	ToQueryOutputWithContext(ctx context.Context) QueryOutput
}

func (*Query) ElementType() reflect.Type {
	return reflect.TypeOf((*Query)(nil))
}

func (i *Query) ToQueryOutput() QueryOutput {
	return i.ToQueryOutputWithContext(context.Background())
}

func (i *Query) ToQueryOutputWithContext(ctx context.Context) QueryOutput {
	return pulumi.ToOutputWithContext(ctx, i).(QueryOutput)
}

func (i *Query) ToQueryPtrOutput() QueryPtrOutput {
	return i.ToQueryPtrOutputWithContext(context.Background())
}

func (i *Query) ToQueryPtrOutputWithContext(ctx context.Context) QueryPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(QueryPtrOutput)
}

type QueryPtrInput interface {
	pulumi.Input

	ToQueryPtrOutput() QueryPtrOutput
	ToQueryPtrOutputWithContext(ctx context.Context) QueryPtrOutput
}

type queryPtrType QueryArgs

func (*queryPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**Query)(nil))
}

func (i *queryPtrType) ToQueryPtrOutput() QueryPtrOutput {
	return i.ToQueryPtrOutputWithContext(context.Background())
}

func (i *queryPtrType) ToQueryPtrOutputWithContext(ctx context.Context) QueryPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(QueryPtrOutput)
}

// QueryArrayInput is an input type that accepts QueryArray and QueryArrayOutput values.
// You can construct a concrete instance of `QueryArrayInput` via:
//
//          QueryArray{ QueryArgs{...} }
type QueryArrayInput interface {
	pulumi.Input

	ToQueryArrayOutput() QueryArrayOutput
	ToQueryArrayOutputWithContext(context.Context) QueryArrayOutput
}

type QueryArray []QueryInput

func (QueryArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Query)(nil)).Elem()
}

func (i QueryArray) ToQueryArrayOutput() QueryArrayOutput {
	return i.ToQueryArrayOutputWithContext(context.Background())
}

func (i QueryArray) ToQueryArrayOutputWithContext(ctx context.Context) QueryArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(QueryArrayOutput)
}

// QueryMapInput is an input type that accepts QueryMap and QueryMapOutput values.
// You can construct a concrete instance of `QueryMapInput` via:
//
//          QueryMap{ "key": QueryArgs{...} }
type QueryMapInput interface {
	pulumi.Input

	ToQueryMapOutput() QueryMapOutput
	ToQueryMapOutputWithContext(context.Context) QueryMapOutput
}

type QueryMap map[string]QueryInput

func (QueryMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Query)(nil)).Elem()
}

func (i QueryMap) ToQueryMapOutput() QueryMapOutput {
	return i.ToQueryMapOutputWithContext(context.Background())
}

func (i QueryMap) ToQueryMapOutputWithContext(ctx context.Context) QueryMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(QueryMapOutput)
}

type QueryOutput struct {
	*pulumi.OutputState
}

func (QueryOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*Query)(nil))
}

func (o QueryOutput) ToQueryOutput() QueryOutput {
	return o
}

func (o QueryOutput) ToQueryOutputWithContext(ctx context.Context) QueryOutput {
	return o
}

func (o QueryOutput) ToQueryPtrOutput() QueryPtrOutput {
	return o.ToQueryPtrOutputWithContext(context.Background())
}

func (o QueryOutput) ToQueryPtrOutputWithContext(ctx context.Context) QueryPtrOutput {
	return o.ApplyT(func(v Query) *Query {
		return &v
	}).(QueryPtrOutput)
}

type QueryPtrOutput struct {
	*pulumi.OutputState
}

func (QueryPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Query)(nil))
}

func (o QueryPtrOutput) ToQueryPtrOutput() QueryPtrOutput {
	return o
}

func (o QueryPtrOutput) ToQueryPtrOutputWithContext(ctx context.Context) QueryPtrOutput {
	return o
}

type QueryArrayOutput struct{ *pulumi.OutputState }

func (QueryArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]Query)(nil))
}

func (o QueryArrayOutput) ToQueryArrayOutput() QueryArrayOutput {
	return o
}

func (o QueryArrayOutput) ToQueryArrayOutputWithContext(ctx context.Context) QueryArrayOutput {
	return o
}

func (o QueryArrayOutput) Index(i pulumi.IntInput) QueryOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) Query {
		return vs[0].([]Query)[vs[1].(int)]
	}).(QueryOutput)
}

type QueryMapOutput struct{ *pulumi.OutputState }

func (QueryMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]Query)(nil))
}

func (o QueryMapOutput) ToQueryMapOutput() QueryMapOutput {
	return o
}

func (o QueryMapOutput) ToQueryMapOutputWithContext(ctx context.Context) QueryMapOutput {
	return o
}

func (o QueryMapOutput) MapIndex(k pulumi.StringInput) QueryOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) Query {
		return vs[0].(map[string]Query)[vs[1].(string)]
	}).(QueryOutput)
}

func init() {
	pulumi.RegisterOutputType(QueryOutput{})
	pulumi.RegisterOutputType(QueryPtrOutput{})
	pulumi.RegisterOutputType(QueryArrayOutput{})
	pulumi.RegisterOutputType(QueryMapOutput{})
}
