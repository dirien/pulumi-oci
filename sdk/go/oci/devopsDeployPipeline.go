// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Deploy Pipeline resource in Oracle Cloud Infrastructure Devops service.
//
// Creates a new deployment pipeline.
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
// 		_, err := oci.NewDevopsDeployPipeline(ctx, "testDeployPipeline", &oci.DevopsDeployPipelineArgs{
// 			ProjectId: pulumi.Any(oci_devops_project.Test_project.Id),
// 			DefinedTags: pulumi.AnyMap{
// 				"foo-namespace.bar-key": pulumi.Any("value"),
// 			},
// 			DeployPipelineParameters: &DevopsDeployPipelineDeployPipelineParametersArgs{
// 				Items: DevopsDeployPipelineDeployPipelineParametersItemArray{
// 					&DevopsDeployPipelineDeployPipelineParametersItemArgs{
// 						Name:         pulumi.Any(_var.Deploy_pipeline_deploy_pipeline_parameters_items_name),
// 						DefaultValue: pulumi.Any(_var.Deploy_pipeline_deploy_pipeline_parameters_items_default_value),
// 						Description:  pulumi.Any(_var.Deploy_pipeline_deploy_pipeline_parameters_items_description),
// 					},
// 				},
// 			},
// 			Description: pulumi.Any(_var.Deploy_pipeline_description),
// 			DisplayName: pulumi.Any(_var.Deploy_pipeline_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"bar-key": pulumi.Any("value"),
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
// DeployPipelines can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/devopsDeployPipeline:DevopsDeployPipeline test_deploy_pipeline "id"
// ```
type DevopsDeployPipeline struct {
	pulumi.CustomResourceState

	// The OCID of the compartment where the pipeline is created.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// List of all artifacts used in the pipeline.
	DeployPipelineArtifacts DevopsDeployPipelineDeployPipelineArtifactsOutput `pulumi:"deployPipelineArtifacts"`
	// List of all environments used in the pipeline.
	DeployPipelineEnvironments DevopsDeployPipelineDeployPipelineEnvironmentsOutput `pulumi:"deployPipelineEnvironments"`
	// (Updatable) Specifies list of parameters present in the deployment pipeline. In case of Update operation, replaces existing parameters list. Merging with existing parameters is not supported.
	DeployPipelineParameters DevopsDeployPipelineDeployPipelineParametersOutput `pulumi:"deployPipelineParameters"`
	// (Updatable) Optional description about the deployment pipeline.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Deployment pipeline display name. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The OCID of a project.
	ProjectId pulumi.StringOutput `pulumi:"projectId"`
	// The current state of the deployment pipeline.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// Time the deployment pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// Time the deployment pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewDevopsDeployPipeline registers a new resource with the given unique name, arguments, and options.
func NewDevopsDeployPipeline(ctx *pulumi.Context,
	name string, args *DevopsDeployPipelineArgs, opts ...pulumi.ResourceOption) (*DevopsDeployPipeline, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ProjectId == nil {
		return nil, errors.New("invalid value for required argument 'ProjectId'")
	}
	var resource DevopsDeployPipeline
	err := ctx.RegisterResource("oci:index/devopsDeployPipeline:DevopsDeployPipeline", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDevopsDeployPipeline gets an existing DevopsDeployPipeline resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDevopsDeployPipeline(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DevopsDeployPipelineState, opts ...pulumi.ResourceOption) (*DevopsDeployPipeline, error) {
	var resource DevopsDeployPipeline
	err := ctx.ReadResource("oci:index/devopsDeployPipeline:DevopsDeployPipeline", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DevopsDeployPipeline resources.
type devopsDeployPipelineState struct {
	// The OCID of the compartment where the pipeline is created.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// List of all artifacts used in the pipeline.
	DeployPipelineArtifacts *DevopsDeployPipelineDeployPipelineArtifacts `pulumi:"deployPipelineArtifacts"`
	// List of all environments used in the pipeline.
	DeployPipelineEnvironments *DevopsDeployPipelineDeployPipelineEnvironments `pulumi:"deployPipelineEnvironments"`
	// (Updatable) Specifies list of parameters present in the deployment pipeline. In case of Update operation, replaces existing parameters list. Merging with existing parameters is not supported.
	DeployPipelineParameters *DevopsDeployPipelineDeployPipelineParameters `pulumi:"deployPipelineParameters"`
	// (Updatable) Optional description about the deployment pipeline.
	Description *string `pulumi:"description"`
	// (Updatable) Deployment pipeline display name. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The OCID of a project.
	ProjectId *string `pulumi:"projectId"`
	// The current state of the deployment pipeline.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// Time the deployment pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// Time the deployment pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type DevopsDeployPipelineState struct {
	// The OCID of the compartment where the pipeline is created.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// List of all artifacts used in the pipeline.
	DeployPipelineArtifacts DevopsDeployPipelineDeployPipelineArtifactsPtrInput
	// List of all environments used in the pipeline.
	DeployPipelineEnvironments DevopsDeployPipelineDeployPipelineEnvironmentsPtrInput
	// (Updatable) Specifies list of parameters present in the deployment pipeline. In case of Update operation, replaces existing parameters list. Merging with existing parameters is not supported.
	DeployPipelineParameters DevopsDeployPipelineDeployPipelineParametersPtrInput
	// (Updatable) Optional description about the deployment pipeline.
	Description pulumi.StringPtrInput
	// (Updatable) Deployment pipeline display name. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// The OCID of a project.
	ProjectId pulumi.StringPtrInput
	// The current state of the deployment pipeline.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// Time the deployment pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// Time the deployment pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringPtrInput
}

func (DevopsDeployPipelineState) ElementType() reflect.Type {
	return reflect.TypeOf((*devopsDeployPipelineState)(nil)).Elem()
}

type devopsDeployPipelineArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Specifies list of parameters present in the deployment pipeline. In case of Update operation, replaces existing parameters list. Merging with existing parameters is not supported.
	DeployPipelineParameters *DevopsDeployPipelineDeployPipelineParameters `pulumi:"deployPipelineParameters"`
	// (Updatable) Optional description about the deployment pipeline.
	Description *string `pulumi:"description"`
	// (Updatable) Deployment pipeline display name. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of a project.
	ProjectId string `pulumi:"projectId"`
}

// The set of arguments for constructing a DevopsDeployPipeline resource.
type DevopsDeployPipelineArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Specifies list of parameters present in the deployment pipeline. In case of Update operation, replaces existing parameters list. Merging with existing parameters is not supported.
	DeployPipelineParameters DevopsDeployPipelineDeployPipelineParametersPtrInput
	// (Updatable) Optional description about the deployment pipeline.
	Description pulumi.StringPtrInput
	// (Updatable) Deployment pipeline display name. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// The OCID of a project.
	ProjectId pulumi.StringInput
}

func (DevopsDeployPipelineArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*devopsDeployPipelineArgs)(nil)).Elem()
}

type DevopsDeployPipelineInput interface {
	pulumi.Input

	ToDevopsDeployPipelineOutput() DevopsDeployPipelineOutput
	ToDevopsDeployPipelineOutputWithContext(ctx context.Context) DevopsDeployPipelineOutput
}

func (*DevopsDeployPipeline) ElementType() reflect.Type {
	return reflect.TypeOf((*DevopsDeployPipeline)(nil))
}

func (i *DevopsDeployPipeline) ToDevopsDeployPipelineOutput() DevopsDeployPipelineOutput {
	return i.ToDevopsDeployPipelineOutputWithContext(context.Background())
}

func (i *DevopsDeployPipeline) ToDevopsDeployPipelineOutputWithContext(ctx context.Context) DevopsDeployPipelineOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DevopsDeployPipelineOutput)
}

func (i *DevopsDeployPipeline) ToDevopsDeployPipelinePtrOutput() DevopsDeployPipelinePtrOutput {
	return i.ToDevopsDeployPipelinePtrOutputWithContext(context.Background())
}

func (i *DevopsDeployPipeline) ToDevopsDeployPipelinePtrOutputWithContext(ctx context.Context) DevopsDeployPipelinePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DevopsDeployPipelinePtrOutput)
}

type DevopsDeployPipelinePtrInput interface {
	pulumi.Input

	ToDevopsDeployPipelinePtrOutput() DevopsDeployPipelinePtrOutput
	ToDevopsDeployPipelinePtrOutputWithContext(ctx context.Context) DevopsDeployPipelinePtrOutput
}

type devopsDeployPipelinePtrType DevopsDeployPipelineArgs

func (*devopsDeployPipelinePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**DevopsDeployPipeline)(nil))
}

func (i *devopsDeployPipelinePtrType) ToDevopsDeployPipelinePtrOutput() DevopsDeployPipelinePtrOutput {
	return i.ToDevopsDeployPipelinePtrOutputWithContext(context.Background())
}

func (i *devopsDeployPipelinePtrType) ToDevopsDeployPipelinePtrOutputWithContext(ctx context.Context) DevopsDeployPipelinePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DevopsDeployPipelinePtrOutput)
}

// DevopsDeployPipelineArrayInput is an input type that accepts DevopsDeployPipelineArray and DevopsDeployPipelineArrayOutput values.
// You can construct a concrete instance of `DevopsDeployPipelineArrayInput` via:
//
//          DevopsDeployPipelineArray{ DevopsDeployPipelineArgs{...} }
type DevopsDeployPipelineArrayInput interface {
	pulumi.Input

	ToDevopsDeployPipelineArrayOutput() DevopsDeployPipelineArrayOutput
	ToDevopsDeployPipelineArrayOutputWithContext(context.Context) DevopsDeployPipelineArrayOutput
}

type DevopsDeployPipelineArray []DevopsDeployPipelineInput

func (DevopsDeployPipelineArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DevopsDeployPipeline)(nil)).Elem()
}

func (i DevopsDeployPipelineArray) ToDevopsDeployPipelineArrayOutput() DevopsDeployPipelineArrayOutput {
	return i.ToDevopsDeployPipelineArrayOutputWithContext(context.Background())
}

func (i DevopsDeployPipelineArray) ToDevopsDeployPipelineArrayOutputWithContext(ctx context.Context) DevopsDeployPipelineArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DevopsDeployPipelineArrayOutput)
}

// DevopsDeployPipelineMapInput is an input type that accepts DevopsDeployPipelineMap and DevopsDeployPipelineMapOutput values.
// You can construct a concrete instance of `DevopsDeployPipelineMapInput` via:
//
//          DevopsDeployPipelineMap{ "key": DevopsDeployPipelineArgs{...} }
type DevopsDeployPipelineMapInput interface {
	pulumi.Input

	ToDevopsDeployPipelineMapOutput() DevopsDeployPipelineMapOutput
	ToDevopsDeployPipelineMapOutputWithContext(context.Context) DevopsDeployPipelineMapOutput
}

type DevopsDeployPipelineMap map[string]DevopsDeployPipelineInput

func (DevopsDeployPipelineMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DevopsDeployPipeline)(nil)).Elem()
}

func (i DevopsDeployPipelineMap) ToDevopsDeployPipelineMapOutput() DevopsDeployPipelineMapOutput {
	return i.ToDevopsDeployPipelineMapOutputWithContext(context.Background())
}

func (i DevopsDeployPipelineMap) ToDevopsDeployPipelineMapOutputWithContext(ctx context.Context) DevopsDeployPipelineMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DevopsDeployPipelineMapOutput)
}

type DevopsDeployPipelineOutput struct {
	*pulumi.OutputState
}

func (DevopsDeployPipelineOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*DevopsDeployPipeline)(nil))
}

func (o DevopsDeployPipelineOutput) ToDevopsDeployPipelineOutput() DevopsDeployPipelineOutput {
	return o
}

func (o DevopsDeployPipelineOutput) ToDevopsDeployPipelineOutputWithContext(ctx context.Context) DevopsDeployPipelineOutput {
	return o
}

func (o DevopsDeployPipelineOutput) ToDevopsDeployPipelinePtrOutput() DevopsDeployPipelinePtrOutput {
	return o.ToDevopsDeployPipelinePtrOutputWithContext(context.Background())
}

func (o DevopsDeployPipelineOutput) ToDevopsDeployPipelinePtrOutputWithContext(ctx context.Context) DevopsDeployPipelinePtrOutput {
	return o.ApplyT(func(v DevopsDeployPipeline) *DevopsDeployPipeline {
		return &v
	}).(DevopsDeployPipelinePtrOutput)
}

type DevopsDeployPipelinePtrOutput struct {
	*pulumi.OutputState
}

func (DevopsDeployPipelinePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DevopsDeployPipeline)(nil))
}

func (o DevopsDeployPipelinePtrOutput) ToDevopsDeployPipelinePtrOutput() DevopsDeployPipelinePtrOutput {
	return o
}

func (o DevopsDeployPipelinePtrOutput) ToDevopsDeployPipelinePtrOutputWithContext(ctx context.Context) DevopsDeployPipelinePtrOutput {
	return o
}

type DevopsDeployPipelineArrayOutput struct{ *pulumi.OutputState }

func (DevopsDeployPipelineArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]DevopsDeployPipeline)(nil))
}

func (o DevopsDeployPipelineArrayOutput) ToDevopsDeployPipelineArrayOutput() DevopsDeployPipelineArrayOutput {
	return o
}

func (o DevopsDeployPipelineArrayOutput) ToDevopsDeployPipelineArrayOutputWithContext(ctx context.Context) DevopsDeployPipelineArrayOutput {
	return o
}

func (o DevopsDeployPipelineArrayOutput) Index(i pulumi.IntInput) DevopsDeployPipelineOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) DevopsDeployPipeline {
		return vs[0].([]DevopsDeployPipeline)[vs[1].(int)]
	}).(DevopsDeployPipelineOutput)
}

type DevopsDeployPipelineMapOutput struct{ *pulumi.OutputState }

func (DevopsDeployPipelineMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]DevopsDeployPipeline)(nil))
}

func (o DevopsDeployPipelineMapOutput) ToDevopsDeployPipelineMapOutput() DevopsDeployPipelineMapOutput {
	return o
}

func (o DevopsDeployPipelineMapOutput) ToDevopsDeployPipelineMapOutputWithContext(ctx context.Context) DevopsDeployPipelineMapOutput {
	return o
}

func (o DevopsDeployPipelineMapOutput) MapIndex(k pulumi.StringInput) DevopsDeployPipelineOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) DevopsDeployPipeline {
		return vs[0].(map[string]DevopsDeployPipeline)[vs[1].(string)]
	}).(DevopsDeployPipelineOutput)
}

func init() {
	pulumi.RegisterOutputType(DevopsDeployPipelineOutput{})
	pulumi.RegisterOutputType(DevopsDeployPipelinePtrOutput{})
	pulumi.RegisterOutputType(DevopsDeployPipelineArrayOutput{})
	pulumi.RegisterOutputType(DevopsDeployPipelineMapOutput{})
}
