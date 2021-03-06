// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Job resource in Oracle Cloud Infrastructure Database Migration service.
//
// Update a Migration Job resource details.
//
// ## Import
//
// Jobs can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/databaseMigrationJob:DatabaseMigrationJob test_job "id"
// ```
type DatabaseMigrationJob struct {
	pulumi.CustomResourceState

	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Name of the job.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The OCID of the job
	JobId pulumi.StringOutput `pulumi:"jobId"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The OCID of the Migration that this job belongs to.
	MigrationId pulumi.StringOutput `pulumi:"migrationId"`
	// Percent progress of job phase.
	Progress DatabaseMigrationJobProgressOutput `pulumi:"progress"`
	// The current state of the migration job.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The time the DB Migration Job was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the DB Migration Job was last updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// Type of unsupported object
	Type pulumi.StringOutput `pulumi:"type"`
	// Database objects not supported.
	UnsupportedObjects DatabaseMigrationJobUnsupportedObjectArrayOutput `pulumi:"unsupportedObjects"`
}

// NewDatabaseMigrationJob registers a new resource with the given unique name, arguments, and options.
func NewDatabaseMigrationJob(ctx *pulumi.Context,
	name string, args *DatabaseMigrationJobArgs, opts ...pulumi.ResourceOption) (*DatabaseMigrationJob, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.JobId == nil {
		return nil, errors.New("invalid value for required argument 'JobId'")
	}
	var resource DatabaseMigrationJob
	err := ctx.RegisterResource("oci:index/databaseMigrationJob:DatabaseMigrationJob", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDatabaseMigrationJob gets an existing DatabaseMigrationJob resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDatabaseMigrationJob(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DatabaseMigrationJobState, opts ...pulumi.ResourceOption) (*DatabaseMigrationJob, error) {
	var resource DatabaseMigrationJob
	err := ctx.ReadResource("oci:index/databaseMigrationJob:DatabaseMigrationJob", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DatabaseMigrationJob resources.
type databaseMigrationJobState struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Name of the job.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the job
	JobId *string `pulumi:"jobId"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The OCID of the Migration that this job belongs to.
	MigrationId *string `pulumi:"migrationId"`
	// Percent progress of job phase.
	Progress *DatabaseMigrationJobProgress `pulumi:"progress"`
	// The current state of the migration job.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The time the DB Migration Job was created. An RFC3339 formatted datetime string
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the DB Migration Job was last updated. An RFC3339 formatted datetime string
	TimeUpdated *string `pulumi:"timeUpdated"`
	// Type of unsupported object
	Type *string `pulumi:"type"`
	// Database objects not supported.
	UnsupportedObjects []DatabaseMigrationJobUnsupportedObject `pulumi:"unsupportedObjects"`
}

type DatabaseMigrationJobState struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Name of the job.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// The OCID of the job
	JobId pulumi.StringPtrInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// The OCID of the Migration that this job belongs to.
	MigrationId pulumi.StringPtrInput
	// Percent progress of job phase.
	Progress DatabaseMigrationJobProgressPtrInput
	// The current state of the migration job.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The time the DB Migration Job was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringPtrInput
	// The time the DB Migration Job was last updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringPtrInput
	// Type of unsupported object
	Type pulumi.StringPtrInput
	// Database objects not supported.
	UnsupportedObjects DatabaseMigrationJobUnsupportedObjectArrayInput
}

func (DatabaseMigrationJobState) ElementType() reflect.Type {
	return reflect.TypeOf((*databaseMigrationJobState)(nil)).Elem()
}

type databaseMigrationJobArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Name of the job.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the job
	JobId string `pulumi:"jobId"`
}

// The set of arguments for constructing a DatabaseMigrationJob resource.
type DatabaseMigrationJobArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Name of the job.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// The OCID of the job
	JobId pulumi.StringInput
}

func (DatabaseMigrationJobArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*databaseMigrationJobArgs)(nil)).Elem()
}

type DatabaseMigrationJobInput interface {
	pulumi.Input

	ToDatabaseMigrationJobOutput() DatabaseMigrationJobOutput
	ToDatabaseMigrationJobOutputWithContext(ctx context.Context) DatabaseMigrationJobOutput
}

func (*DatabaseMigrationJob) ElementType() reflect.Type {
	return reflect.TypeOf((*DatabaseMigrationJob)(nil))
}

func (i *DatabaseMigrationJob) ToDatabaseMigrationJobOutput() DatabaseMigrationJobOutput {
	return i.ToDatabaseMigrationJobOutputWithContext(context.Background())
}

func (i *DatabaseMigrationJob) ToDatabaseMigrationJobOutputWithContext(ctx context.Context) DatabaseMigrationJobOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseMigrationJobOutput)
}

func (i *DatabaseMigrationJob) ToDatabaseMigrationJobPtrOutput() DatabaseMigrationJobPtrOutput {
	return i.ToDatabaseMigrationJobPtrOutputWithContext(context.Background())
}

func (i *DatabaseMigrationJob) ToDatabaseMigrationJobPtrOutputWithContext(ctx context.Context) DatabaseMigrationJobPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseMigrationJobPtrOutput)
}

type DatabaseMigrationJobPtrInput interface {
	pulumi.Input

	ToDatabaseMigrationJobPtrOutput() DatabaseMigrationJobPtrOutput
	ToDatabaseMigrationJobPtrOutputWithContext(ctx context.Context) DatabaseMigrationJobPtrOutput
}

type databaseMigrationJobPtrType DatabaseMigrationJobArgs

func (*databaseMigrationJobPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**DatabaseMigrationJob)(nil))
}

func (i *databaseMigrationJobPtrType) ToDatabaseMigrationJobPtrOutput() DatabaseMigrationJobPtrOutput {
	return i.ToDatabaseMigrationJobPtrOutputWithContext(context.Background())
}

func (i *databaseMigrationJobPtrType) ToDatabaseMigrationJobPtrOutputWithContext(ctx context.Context) DatabaseMigrationJobPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseMigrationJobPtrOutput)
}

// DatabaseMigrationJobArrayInput is an input type that accepts DatabaseMigrationJobArray and DatabaseMigrationJobArrayOutput values.
// You can construct a concrete instance of `DatabaseMigrationJobArrayInput` via:
//
//          DatabaseMigrationJobArray{ DatabaseMigrationJobArgs{...} }
type DatabaseMigrationJobArrayInput interface {
	pulumi.Input

	ToDatabaseMigrationJobArrayOutput() DatabaseMigrationJobArrayOutput
	ToDatabaseMigrationJobArrayOutputWithContext(context.Context) DatabaseMigrationJobArrayOutput
}

type DatabaseMigrationJobArray []DatabaseMigrationJobInput

func (DatabaseMigrationJobArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DatabaseMigrationJob)(nil)).Elem()
}

func (i DatabaseMigrationJobArray) ToDatabaseMigrationJobArrayOutput() DatabaseMigrationJobArrayOutput {
	return i.ToDatabaseMigrationJobArrayOutputWithContext(context.Background())
}

func (i DatabaseMigrationJobArray) ToDatabaseMigrationJobArrayOutputWithContext(ctx context.Context) DatabaseMigrationJobArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseMigrationJobArrayOutput)
}

// DatabaseMigrationJobMapInput is an input type that accepts DatabaseMigrationJobMap and DatabaseMigrationJobMapOutput values.
// You can construct a concrete instance of `DatabaseMigrationJobMapInput` via:
//
//          DatabaseMigrationJobMap{ "key": DatabaseMigrationJobArgs{...} }
type DatabaseMigrationJobMapInput interface {
	pulumi.Input

	ToDatabaseMigrationJobMapOutput() DatabaseMigrationJobMapOutput
	ToDatabaseMigrationJobMapOutputWithContext(context.Context) DatabaseMigrationJobMapOutput
}

type DatabaseMigrationJobMap map[string]DatabaseMigrationJobInput

func (DatabaseMigrationJobMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DatabaseMigrationJob)(nil)).Elem()
}

func (i DatabaseMigrationJobMap) ToDatabaseMigrationJobMapOutput() DatabaseMigrationJobMapOutput {
	return i.ToDatabaseMigrationJobMapOutputWithContext(context.Background())
}

func (i DatabaseMigrationJobMap) ToDatabaseMigrationJobMapOutputWithContext(ctx context.Context) DatabaseMigrationJobMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseMigrationJobMapOutput)
}

type DatabaseMigrationJobOutput struct {
	*pulumi.OutputState
}

func (DatabaseMigrationJobOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*DatabaseMigrationJob)(nil))
}

func (o DatabaseMigrationJobOutput) ToDatabaseMigrationJobOutput() DatabaseMigrationJobOutput {
	return o
}

func (o DatabaseMigrationJobOutput) ToDatabaseMigrationJobOutputWithContext(ctx context.Context) DatabaseMigrationJobOutput {
	return o
}

func (o DatabaseMigrationJobOutput) ToDatabaseMigrationJobPtrOutput() DatabaseMigrationJobPtrOutput {
	return o.ToDatabaseMigrationJobPtrOutputWithContext(context.Background())
}

func (o DatabaseMigrationJobOutput) ToDatabaseMigrationJobPtrOutputWithContext(ctx context.Context) DatabaseMigrationJobPtrOutput {
	return o.ApplyT(func(v DatabaseMigrationJob) *DatabaseMigrationJob {
		return &v
	}).(DatabaseMigrationJobPtrOutput)
}

type DatabaseMigrationJobPtrOutput struct {
	*pulumi.OutputState
}

func (DatabaseMigrationJobPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DatabaseMigrationJob)(nil))
}

func (o DatabaseMigrationJobPtrOutput) ToDatabaseMigrationJobPtrOutput() DatabaseMigrationJobPtrOutput {
	return o
}

func (o DatabaseMigrationJobPtrOutput) ToDatabaseMigrationJobPtrOutputWithContext(ctx context.Context) DatabaseMigrationJobPtrOutput {
	return o
}

type DatabaseMigrationJobArrayOutput struct{ *pulumi.OutputState }

func (DatabaseMigrationJobArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]DatabaseMigrationJob)(nil))
}

func (o DatabaseMigrationJobArrayOutput) ToDatabaseMigrationJobArrayOutput() DatabaseMigrationJobArrayOutput {
	return o
}

func (o DatabaseMigrationJobArrayOutput) ToDatabaseMigrationJobArrayOutputWithContext(ctx context.Context) DatabaseMigrationJobArrayOutput {
	return o
}

func (o DatabaseMigrationJobArrayOutput) Index(i pulumi.IntInput) DatabaseMigrationJobOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) DatabaseMigrationJob {
		return vs[0].([]DatabaseMigrationJob)[vs[1].(int)]
	}).(DatabaseMigrationJobOutput)
}

type DatabaseMigrationJobMapOutput struct{ *pulumi.OutputState }

func (DatabaseMigrationJobMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]DatabaseMigrationJob)(nil))
}

func (o DatabaseMigrationJobMapOutput) ToDatabaseMigrationJobMapOutput() DatabaseMigrationJobMapOutput {
	return o
}

func (o DatabaseMigrationJobMapOutput) ToDatabaseMigrationJobMapOutputWithContext(ctx context.Context) DatabaseMigrationJobMapOutput {
	return o
}

func (o DatabaseMigrationJobMapOutput) MapIndex(k pulumi.StringInput) DatabaseMigrationJobOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) DatabaseMigrationJob {
		return vs[0].(map[string]DatabaseMigrationJob)[vs[1].(string)]
	}).(DatabaseMigrationJobOutput)
}

func init() {
	pulumi.RegisterOutputType(DatabaseMigrationJobOutput{})
	pulumi.RegisterOutputType(DatabaseMigrationJobPtrOutput{})
	pulumi.RegisterOutputType(DatabaseMigrationJobArrayOutput{})
	pulumi.RegisterOutputType(DatabaseMigrationJobMapOutput{})
}
