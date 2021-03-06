// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Deployment resource in Oracle Cloud Infrastructure Devops service.
//
// Creates a new deployment.
//
// ## Import
//
// Deployments can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/devopsDeployment:DevopsDeployment test_deployment "id"
// ```
type DevopsDeployment struct {
	pulumi.CustomResourceState

	// The OCID of a compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// Specifies the list of artifact override arguments at the time of deployment.
	DeployArtifactOverrideArguments DevopsDeploymentDeployArtifactOverrideArgumentsOutput `pulumi:"deployArtifactOverrideArguments"`
	// List of all artifacts used in the pipeline.
	DeployPipelineArtifacts DevopsDeploymentDeployPipelineArtifactsOutput `pulumi:"deployPipelineArtifacts"`
	// List of all environments used in the pipeline.
	DeployPipelineEnvironments DevopsDeploymentDeployPipelineEnvironmentsOutput `pulumi:"deployPipelineEnvironments"`
	// The OCID of a pipeline.
	DeployPipelineId pulumi.StringOutput `pulumi:"deployPipelineId"`
	// Specifies the OCID of the stage to be redeployed.
	DeployStageId pulumi.StringOutput `pulumi:"deployStageId"`
	// Specifies list of arguments passed along with the deployment.
	DeploymentArguments DevopsDeploymentDeploymentArgumentsOutput `pulumi:"deploymentArguments"`
	// The execution progress details of a deployment.
	DeploymentExecutionProgress DevopsDeploymentDeploymentExecutionProgressOutput `pulumi:"deploymentExecutionProgress"`
	// (Updatable) Specifies type for this deployment.
	DeploymentType pulumi.StringOutput `pulumi:"deploymentType"`
	// (Updatable) Deployment display name. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Specifies the OCID of the previous deployment to be redeployed.
	PreviousDeploymentId pulumi.StringOutput `pulumi:"previousDeploymentId"`
	// The OCID of a project.
	ProjectId pulumi.StringOutput `pulumi:"projectId"`
	// The current state of the deployment.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// Time the deployment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// Time the deployment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewDevopsDeployment registers a new resource with the given unique name, arguments, and options.
func NewDevopsDeployment(ctx *pulumi.Context,
	name string, args *DevopsDeploymentArgs, opts ...pulumi.ResourceOption) (*DevopsDeployment, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.DeployPipelineId == nil {
		return nil, errors.New("invalid value for required argument 'DeployPipelineId'")
	}
	if args.DeploymentType == nil {
		return nil, errors.New("invalid value for required argument 'DeploymentType'")
	}
	var resource DevopsDeployment
	err := ctx.RegisterResource("oci:index/devopsDeployment:DevopsDeployment", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDevopsDeployment gets an existing DevopsDeployment resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDevopsDeployment(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DevopsDeploymentState, opts ...pulumi.ResourceOption) (*DevopsDeployment, error) {
	var resource DevopsDeployment
	err := ctx.ReadResource("oci:index/devopsDeployment:DevopsDeployment", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DevopsDeployment resources.
type devopsDeploymentState struct {
	// The OCID of a compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Specifies the list of artifact override arguments at the time of deployment.
	DeployArtifactOverrideArguments *DevopsDeploymentDeployArtifactOverrideArguments `pulumi:"deployArtifactOverrideArguments"`
	// List of all artifacts used in the pipeline.
	DeployPipelineArtifacts *DevopsDeploymentDeployPipelineArtifacts `pulumi:"deployPipelineArtifacts"`
	// List of all environments used in the pipeline.
	DeployPipelineEnvironments *DevopsDeploymentDeployPipelineEnvironments `pulumi:"deployPipelineEnvironments"`
	// The OCID of a pipeline.
	DeployPipelineId *string `pulumi:"deployPipelineId"`
	// Specifies the OCID of the stage to be redeployed.
	DeployStageId *string `pulumi:"deployStageId"`
	// Specifies list of arguments passed along with the deployment.
	DeploymentArguments *DevopsDeploymentDeploymentArguments `pulumi:"deploymentArguments"`
	// The execution progress details of a deployment.
	DeploymentExecutionProgress *DevopsDeploymentDeploymentExecutionProgress `pulumi:"deploymentExecutionProgress"`
	// (Updatable) Specifies type for this deployment.
	DeploymentType *string `pulumi:"deploymentType"`
	// (Updatable) Deployment display name. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Specifies the OCID of the previous deployment to be redeployed.
	PreviousDeploymentId *string `pulumi:"previousDeploymentId"`
	// The OCID of a project.
	ProjectId *string `pulumi:"projectId"`
	// The current state of the deployment.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// Time the deployment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// Time the deployment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type DevopsDeploymentState struct {
	// The OCID of a compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// Specifies the list of artifact override arguments at the time of deployment.
	DeployArtifactOverrideArguments DevopsDeploymentDeployArtifactOverrideArgumentsPtrInput
	// List of all artifacts used in the pipeline.
	DeployPipelineArtifacts DevopsDeploymentDeployPipelineArtifactsPtrInput
	// List of all environments used in the pipeline.
	DeployPipelineEnvironments DevopsDeploymentDeployPipelineEnvironmentsPtrInput
	// The OCID of a pipeline.
	DeployPipelineId pulumi.StringPtrInput
	// Specifies the OCID of the stage to be redeployed.
	DeployStageId pulumi.StringPtrInput
	// Specifies list of arguments passed along with the deployment.
	DeploymentArguments DevopsDeploymentDeploymentArgumentsPtrInput
	// The execution progress details of a deployment.
	DeploymentExecutionProgress DevopsDeploymentDeploymentExecutionProgressPtrInput
	// (Updatable) Specifies type for this deployment.
	DeploymentType pulumi.StringPtrInput
	// (Updatable) Deployment display name. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// Specifies the OCID of the previous deployment to be redeployed.
	PreviousDeploymentId pulumi.StringPtrInput
	// The OCID of a project.
	ProjectId pulumi.StringPtrInput
	// The current state of the deployment.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// Time the deployment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// Time the deployment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringPtrInput
}

func (DevopsDeploymentState) ElementType() reflect.Type {
	return reflect.TypeOf((*devopsDeploymentState)(nil)).Elem()
}

type devopsDeploymentArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Specifies the list of artifact override arguments at the time of deployment.
	DeployArtifactOverrideArguments *DevopsDeploymentDeployArtifactOverrideArguments `pulumi:"deployArtifactOverrideArguments"`
	// The OCID of a pipeline.
	DeployPipelineId string `pulumi:"deployPipelineId"`
	// Specifies the OCID of the stage to be redeployed.
	DeployStageId *string `pulumi:"deployStageId"`
	// Specifies list of arguments passed along with the deployment.
	DeploymentArguments *DevopsDeploymentDeploymentArguments `pulumi:"deploymentArguments"`
	// (Updatable) Specifies type for this deployment.
	DeploymentType string `pulumi:"deploymentType"`
	// (Updatable) Deployment display name. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Specifies the OCID of the previous deployment to be redeployed.
	PreviousDeploymentId *string `pulumi:"previousDeploymentId"`
}

// The set of arguments for constructing a DevopsDeployment resource.
type DevopsDeploymentArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// Specifies the list of artifact override arguments at the time of deployment.
	DeployArtifactOverrideArguments DevopsDeploymentDeployArtifactOverrideArgumentsPtrInput
	// The OCID of a pipeline.
	DeployPipelineId pulumi.StringInput
	// Specifies the OCID of the stage to be redeployed.
	DeployStageId pulumi.StringPtrInput
	// Specifies list of arguments passed along with the deployment.
	DeploymentArguments DevopsDeploymentDeploymentArgumentsPtrInput
	// (Updatable) Specifies type for this deployment.
	DeploymentType pulumi.StringInput
	// (Updatable) Deployment display name. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// Specifies the OCID of the previous deployment to be redeployed.
	PreviousDeploymentId pulumi.StringPtrInput
}

func (DevopsDeploymentArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*devopsDeploymentArgs)(nil)).Elem()
}

type DevopsDeploymentInput interface {
	pulumi.Input

	ToDevopsDeploymentOutput() DevopsDeploymentOutput
	ToDevopsDeploymentOutputWithContext(ctx context.Context) DevopsDeploymentOutput
}

func (*DevopsDeployment) ElementType() reflect.Type {
	return reflect.TypeOf((*DevopsDeployment)(nil))
}

func (i *DevopsDeployment) ToDevopsDeploymentOutput() DevopsDeploymentOutput {
	return i.ToDevopsDeploymentOutputWithContext(context.Background())
}

func (i *DevopsDeployment) ToDevopsDeploymentOutputWithContext(ctx context.Context) DevopsDeploymentOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DevopsDeploymentOutput)
}

func (i *DevopsDeployment) ToDevopsDeploymentPtrOutput() DevopsDeploymentPtrOutput {
	return i.ToDevopsDeploymentPtrOutputWithContext(context.Background())
}

func (i *DevopsDeployment) ToDevopsDeploymentPtrOutputWithContext(ctx context.Context) DevopsDeploymentPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DevopsDeploymentPtrOutput)
}

type DevopsDeploymentPtrInput interface {
	pulumi.Input

	ToDevopsDeploymentPtrOutput() DevopsDeploymentPtrOutput
	ToDevopsDeploymentPtrOutputWithContext(ctx context.Context) DevopsDeploymentPtrOutput
}

type devopsDeploymentPtrType DevopsDeploymentArgs

func (*devopsDeploymentPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**DevopsDeployment)(nil))
}

func (i *devopsDeploymentPtrType) ToDevopsDeploymentPtrOutput() DevopsDeploymentPtrOutput {
	return i.ToDevopsDeploymentPtrOutputWithContext(context.Background())
}

func (i *devopsDeploymentPtrType) ToDevopsDeploymentPtrOutputWithContext(ctx context.Context) DevopsDeploymentPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DevopsDeploymentPtrOutput)
}

// DevopsDeploymentArrayInput is an input type that accepts DevopsDeploymentArray and DevopsDeploymentArrayOutput values.
// You can construct a concrete instance of `DevopsDeploymentArrayInput` via:
//
//          DevopsDeploymentArray{ DevopsDeploymentArgs{...} }
type DevopsDeploymentArrayInput interface {
	pulumi.Input

	ToDevopsDeploymentArrayOutput() DevopsDeploymentArrayOutput
	ToDevopsDeploymentArrayOutputWithContext(context.Context) DevopsDeploymentArrayOutput
}

type DevopsDeploymentArray []DevopsDeploymentInput

func (DevopsDeploymentArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DevopsDeployment)(nil)).Elem()
}

func (i DevopsDeploymentArray) ToDevopsDeploymentArrayOutput() DevopsDeploymentArrayOutput {
	return i.ToDevopsDeploymentArrayOutputWithContext(context.Background())
}

func (i DevopsDeploymentArray) ToDevopsDeploymentArrayOutputWithContext(ctx context.Context) DevopsDeploymentArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DevopsDeploymentArrayOutput)
}

// DevopsDeploymentMapInput is an input type that accepts DevopsDeploymentMap and DevopsDeploymentMapOutput values.
// You can construct a concrete instance of `DevopsDeploymentMapInput` via:
//
//          DevopsDeploymentMap{ "key": DevopsDeploymentArgs{...} }
type DevopsDeploymentMapInput interface {
	pulumi.Input

	ToDevopsDeploymentMapOutput() DevopsDeploymentMapOutput
	ToDevopsDeploymentMapOutputWithContext(context.Context) DevopsDeploymentMapOutput
}

type DevopsDeploymentMap map[string]DevopsDeploymentInput

func (DevopsDeploymentMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DevopsDeployment)(nil)).Elem()
}

func (i DevopsDeploymentMap) ToDevopsDeploymentMapOutput() DevopsDeploymentMapOutput {
	return i.ToDevopsDeploymentMapOutputWithContext(context.Background())
}

func (i DevopsDeploymentMap) ToDevopsDeploymentMapOutputWithContext(ctx context.Context) DevopsDeploymentMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DevopsDeploymentMapOutput)
}

type DevopsDeploymentOutput struct {
	*pulumi.OutputState
}

func (DevopsDeploymentOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*DevopsDeployment)(nil))
}

func (o DevopsDeploymentOutput) ToDevopsDeploymentOutput() DevopsDeploymentOutput {
	return o
}

func (o DevopsDeploymentOutput) ToDevopsDeploymentOutputWithContext(ctx context.Context) DevopsDeploymentOutput {
	return o
}

func (o DevopsDeploymentOutput) ToDevopsDeploymentPtrOutput() DevopsDeploymentPtrOutput {
	return o.ToDevopsDeploymentPtrOutputWithContext(context.Background())
}

func (o DevopsDeploymentOutput) ToDevopsDeploymentPtrOutputWithContext(ctx context.Context) DevopsDeploymentPtrOutput {
	return o.ApplyT(func(v DevopsDeployment) *DevopsDeployment {
		return &v
	}).(DevopsDeploymentPtrOutput)
}

type DevopsDeploymentPtrOutput struct {
	*pulumi.OutputState
}

func (DevopsDeploymentPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DevopsDeployment)(nil))
}

func (o DevopsDeploymentPtrOutput) ToDevopsDeploymentPtrOutput() DevopsDeploymentPtrOutput {
	return o
}

func (o DevopsDeploymentPtrOutput) ToDevopsDeploymentPtrOutputWithContext(ctx context.Context) DevopsDeploymentPtrOutput {
	return o
}

type DevopsDeploymentArrayOutput struct{ *pulumi.OutputState }

func (DevopsDeploymentArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]DevopsDeployment)(nil))
}

func (o DevopsDeploymentArrayOutput) ToDevopsDeploymentArrayOutput() DevopsDeploymentArrayOutput {
	return o
}

func (o DevopsDeploymentArrayOutput) ToDevopsDeploymentArrayOutputWithContext(ctx context.Context) DevopsDeploymentArrayOutput {
	return o
}

func (o DevopsDeploymentArrayOutput) Index(i pulumi.IntInput) DevopsDeploymentOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) DevopsDeployment {
		return vs[0].([]DevopsDeployment)[vs[1].(int)]
	}).(DevopsDeploymentOutput)
}

type DevopsDeploymentMapOutput struct{ *pulumi.OutputState }

func (DevopsDeploymentMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]DevopsDeployment)(nil))
}

func (o DevopsDeploymentMapOutput) ToDevopsDeploymentMapOutput() DevopsDeploymentMapOutput {
	return o
}

func (o DevopsDeploymentMapOutput) ToDevopsDeploymentMapOutputWithContext(ctx context.Context) DevopsDeploymentMapOutput {
	return o
}

func (o DevopsDeploymentMapOutput) MapIndex(k pulumi.StringInput) DevopsDeploymentOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) DevopsDeployment {
		return vs[0].(map[string]DevopsDeployment)[vs[1].(string)]
	}).(DevopsDeploymentOutput)
}

func init() {
	pulumi.RegisterOutputType(DevopsDeploymentOutput{})
	pulumi.RegisterOutputType(DevopsDeploymentPtrOutput{})
	pulumi.RegisterOutputType(DevopsDeploymentArrayOutput{})
	pulumi.RegisterOutputType(DevopsDeploymentMapOutput{})
}
