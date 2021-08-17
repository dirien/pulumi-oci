// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Log resource in Oracle Cloud Infrastructure Logging service.
//
// Creates a log within the specified log group. This call fails if a log group has already been created
// with the same displayName or (service, resource, category) triplet.
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
// 		_, err := oci.NewLoggingLog(ctx, "testLog", &oci.LoggingLogArgs{
// 			DisplayName: pulumi.Any(_var.Log_display_name),
// 			LogGroupId:  pulumi.Any(oci_logging_log_group.Test_log_group.Id),
// 			LogType:     pulumi.Any(_var.Log_log_type),
// 			Configuration: &LoggingLogConfigurationArgs{
// 				Source: &LoggingLogConfigurationSourceArgs{
// 					Category:   pulumi.Any(_var.Log_configuration_source_category),
// 					Resource:   pulumi.Any(_var.Log_configuration_source_resource),
// 					Service:    pulumi.Any(_var.Log_configuration_source_service),
// 					SourceType: pulumi.Any(_var.Log_configuration_source_source_type),
// 				},
// 				CompartmentId: pulumi.Any(_var.Compartment_id),
// 			},
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
// 			IsEnabled:         pulumi.Any(_var.Log_is_enabled),
// 			RetentionDuration: pulumi.Any(_var.Log_retention_duration),
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
// Logs can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/loggingLog:LoggingLog test_log "logGroupId/{logGroupId}/logId/{logId}"
// ```
type LoggingLog struct {
	pulumi.CustomResourceState

	// The OCID of the compartment that the resource belongs to.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Log object configuration.
	Configuration LoggingLogConfigurationOutput `pulumi:"configuration"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// (Updatable) Whether or not this resource is currently enabled.
	IsEnabled pulumi.BoolOutput `pulumi:"isEnabled"`
	// (Updatable) OCID of a log group to work with.
	LogGroupId pulumi.StringOutput `pulumi:"logGroupId"`
	// The logType that the log object is for, whether custom or service.
	LogType pulumi.StringOutput `pulumi:"logType"`
	// (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on).
	RetentionDuration pulumi.IntOutput `pulumi:"retentionDuration"`
	// The pipeline state.
	State pulumi.StringOutput `pulumi:"state"`
	// The OCID of the tenancy.
	TenancyId pulumi.StringOutput `pulumi:"tenancyId"`
	// Time the resource was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// Time the resource was last modified.
	TimeLastModified pulumi.StringOutput `pulumi:"timeLastModified"`
}

// NewLoggingLog registers a new resource with the given unique name, arguments, and options.
func NewLoggingLog(ctx *pulumi.Context,
	name string, args *LoggingLogArgs, opts ...pulumi.ResourceOption) (*LoggingLog, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.LogGroupId == nil {
		return nil, errors.New("invalid value for required argument 'LogGroupId'")
	}
	if args.LogType == nil {
		return nil, errors.New("invalid value for required argument 'LogType'")
	}
	var resource LoggingLog
	err := ctx.RegisterResource("oci:index/loggingLog:LoggingLog", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLoggingLog gets an existing LoggingLog resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLoggingLog(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LoggingLogState, opts ...pulumi.ResourceOption) (*LoggingLog, error) {
	var resource LoggingLog
	err := ctx.ReadResource("oci:index/loggingLog:LoggingLog", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LoggingLog resources.
type loggingLogState struct {
	// The OCID of the compartment that the resource belongs to.
	CompartmentId *string `pulumi:"compartmentId"`
	// Log object configuration.
	Configuration *LoggingLogConfiguration `pulumi:"configuration"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Whether or not this resource is currently enabled.
	IsEnabled *bool `pulumi:"isEnabled"`
	// (Updatable) OCID of a log group to work with.
	LogGroupId *string `pulumi:"logGroupId"`
	// The logType that the log object is for, whether custom or service.
	LogType *string `pulumi:"logType"`
	// (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on).
	RetentionDuration *int `pulumi:"retentionDuration"`
	// The pipeline state.
	State *string `pulumi:"state"`
	// The OCID of the tenancy.
	TenancyId *string `pulumi:"tenancyId"`
	// Time the resource was created.
	TimeCreated *string `pulumi:"timeCreated"`
	// Time the resource was last modified.
	TimeLastModified *string `pulumi:"timeLastModified"`
}

type LoggingLogState struct {
	// The OCID of the compartment that the resource belongs to.
	CompartmentId pulumi.StringPtrInput
	// Log object configuration.
	Configuration LoggingLogConfigurationPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Whether or not this resource is currently enabled.
	IsEnabled pulumi.BoolPtrInput
	// (Updatable) OCID of a log group to work with.
	LogGroupId pulumi.StringPtrInput
	// The logType that the log object is for, whether custom or service.
	LogType pulumi.StringPtrInput
	// (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on).
	RetentionDuration pulumi.IntPtrInput
	// The pipeline state.
	State pulumi.StringPtrInput
	// The OCID of the tenancy.
	TenancyId pulumi.StringPtrInput
	// Time the resource was created.
	TimeCreated pulumi.StringPtrInput
	// Time the resource was last modified.
	TimeLastModified pulumi.StringPtrInput
}

func (LoggingLogState) ElementType() reflect.Type {
	return reflect.TypeOf((*loggingLogState)(nil)).Elem()
}

type loggingLogArgs struct {
	// Log object configuration.
	Configuration *LoggingLogConfiguration `pulumi:"configuration"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Whether or not this resource is currently enabled.
	IsEnabled *bool `pulumi:"isEnabled"`
	// (Updatable) OCID of a log group to work with.
	LogGroupId string `pulumi:"logGroupId"`
	// The logType that the log object is for, whether custom or service.
	LogType string `pulumi:"logType"`
	// (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on).
	RetentionDuration *int `pulumi:"retentionDuration"`
}

// The set of arguments for constructing a LoggingLog resource.
type LoggingLogArgs struct {
	// Log object configuration.
	Configuration LoggingLogConfigurationPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Whether or not this resource is currently enabled.
	IsEnabled pulumi.BoolPtrInput
	// (Updatable) OCID of a log group to work with.
	LogGroupId pulumi.StringInput
	// The logType that the log object is for, whether custom or service.
	LogType pulumi.StringInput
	// (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on).
	RetentionDuration pulumi.IntPtrInput
}

func (LoggingLogArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*loggingLogArgs)(nil)).Elem()
}

type LoggingLogInput interface {
	pulumi.Input

	ToLoggingLogOutput() LoggingLogOutput
	ToLoggingLogOutputWithContext(ctx context.Context) LoggingLogOutput
}

func (*LoggingLog) ElementType() reflect.Type {
	return reflect.TypeOf((*LoggingLog)(nil))
}

func (i *LoggingLog) ToLoggingLogOutput() LoggingLogOutput {
	return i.ToLoggingLogOutputWithContext(context.Background())
}

func (i *LoggingLog) ToLoggingLogOutputWithContext(ctx context.Context) LoggingLogOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoggingLogOutput)
}

func (i *LoggingLog) ToLoggingLogPtrOutput() LoggingLogPtrOutput {
	return i.ToLoggingLogPtrOutputWithContext(context.Background())
}

func (i *LoggingLog) ToLoggingLogPtrOutputWithContext(ctx context.Context) LoggingLogPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoggingLogPtrOutput)
}

type LoggingLogPtrInput interface {
	pulumi.Input

	ToLoggingLogPtrOutput() LoggingLogPtrOutput
	ToLoggingLogPtrOutputWithContext(ctx context.Context) LoggingLogPtrOutput
}

type loggingLogPtrType LoggingLogArgs

func (*loggingLogPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**LoggingLog)(nil))
}

func (i *loggingLogPtrType) ToLoggingLogPtrOutput() LoggingLogPtrOutput {
	return i.ToLoggingLogPtrOutputWithContext(context.Background())
}

func (i *loggingLogPtrType) ToLoggingLogPtrOutputWithContext(ctx context.Context) LoggingLogPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoggingLogPtrOutput)
}

// LoggingLogArrayInput is an input type that accepts LoggingLogArray and LoggingLogArrayOutput values.
// You can construct a concrete instance of `LoggingLogArrayInput` via:
//
//          LoggingLogArray{ LoggingLogArgs{...} }
type LoggingLogArrayInput interface {
	pulumi.Input

	ToLoggingLogArrayOutput() LoggingLogArrayOutput
	ToLoggingLogArrayOutputWithContext(context.Context) LoggingLogArrayOutput
}

type LoggingLogArray []LoggingLogInput

func (LoggingLogArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LoggingLog)(nil)).Elem()
}

func (i LoggingLogArray) ToLoggingLogArrayOutput() LoggingLogArrayOutput {
	return i.ToLoggingLogArrayOutputWithContext(context.Background())
}

func (i LoggingLogArray) ToLoggingLogArrayOutputWithContext(ctx context.Context) LoggingLogArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoggingLogArrayOutput)
}

// LoggingLogMapInput is an input type that accepts LoggingLogMap and LoggingLogMapOutput values.
// You can construct a concrete instance of `LoggingLogMapInput` via:
//
//          LoggingLogMap{ "key": LoggingLogArgs{...} }
type LoggingLogMapInput interface {
	pulumi.Input

	ToLoggingLogMapOutput() LoggingLogMapOutput
	ToLoggingLogMapOutputWithContext(context.Context) LoggingLogMapOutput
}

type LoggingLogMap map[string]LoggingLogInput

func (LoggingLogMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LoggingLog)(nil)).Elem()
}

func (i LoggingLogMap) ToLoggingLogMapOutput() LoggingLogMapOutput {
	return i.ToLoggingLogMapOutputWithContext(context.Background())
}

func (i LoggingLogMap) ToLoggingLogMapOutputWithContext(ctx context.Context) LoggingLogMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoggingLogMapOutput)
}

type LoggingLogOutput struct {
	*pulumi.OutputState
}

func (LoggingLogOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LoggingLog)(nil))
}

func (o LoggingLogOutput) ToLoggingLogOutput() LoggingLogOutput {
	return o
}

func (o LoggingLogOutput) ToLoggingLogOutputWithContext(ctx context.Context) LoggingLogOutput {
	return o
}

func (o LoggingLogOutput) ToLoggingLogPtrOutput() LoggingLogPtrOutput {
	return o.ToLoggingLogPtrOutputWithContext(context.Background())
}

func (o LoggingLogOutput) ToLoggingLogPtrOutputWithContext(ctx context.Context) LoggingLogPtrOutput {
	return o.ApplyT(func(v LoggingLog) *LoggingLog {
		return &v
	}).(LoggingLogPtrOutput)
}

type LoggingLogPtrOutput struct {
	*pulumi.OutputState
}

func (LoggingLogPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**LoggingLog)(nil))
}

func (o LoggingLogPtrOutput) ToLoggingLogPtrOutput() LoggingLogPtrOutput {
	return o
}

func (o LoggingLogPtrOutput) ToLoggingLogPtrOutputWithContext(ctx context.Context) LoggingLogPtrOutput {
	return o
}

type LoggingLogArrayOutput struct{ *pulumi.OutputState }

func (LoggingLogArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]LoggingLog)(nil))
}

func (o LoggingLogArrayOutput) ToLoggingLogArrayOutput() LoggingLogArrayOutput {
	return o
}

func (o LoggingLogArrayOutput) ToLoggingLogArrayOutputWithContext(ctx context.Context) LoggingLogArrayOutput {
	return o
}

func (o LoggingLogArrayOutput) Index(i pulumi.IntInput) LoggingLogOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) LoggingLog {
		return vs[0].([]LoggingLog)[vs[1].(int)]
	}).(LoggingLogOutput)
}

type LoggingLogMapOutput struct{ *pulumi.OutputState }

func (LoggingLogMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]LoggingLog)(nil))
}

func (o LoggingLogMapOutput) ToLoggingLogMapOutput() LoggingLogMapOutput {
	return o
}

func (o LoggingLogMapOutput) ToLoggingLogMapOutputWithContext(ctx context.Context) LoggingLogMapOutput {
	return o
}

func (o LoggingLogMapOutput) MapIndex(k pulumi.StringInput) LoggingLogOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) LoggingLog {
		return vs[0].(map[string]LoggingLog)[vs[1].(string)]
	}).(LoggingLogOutput)
}

func init() {
	pulumi.RegisterOutputType(LoggingLogOutput{})
	pulumi.RegisterOutputType(LoggingLogPtrOutput{})
	pulumi.RegisterOutputType(LoggingLogArrayOutput{})
	pulumi.RegisterOutputType(LoggingLogMapOutput{})
}