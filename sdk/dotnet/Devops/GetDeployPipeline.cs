// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Devops
{
    public static class GetDeployPipeline
    {
        /// <summary>
        /// This data source provides details about a specific Deploy Pipeline resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a deployment pipeline by identifier.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testDeployPipeline = Output.Create(Oci.Devops.GetDeployPipeline.InvokeAsync(new Oci.Devops.GetDeployPipelineArgs
        ///         {
        ///             DeployPipelineId = oci_devops_deploy_pipeline.Test_deploy_pipeline.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDeployPipelineResult> InvokeAsync(GetDeployPipelineArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDeployPipelineResult>("oci:devops/getDeployPipeline:getDeployPipeline", args ?? new GetDeployPipelineArgs(), options.WithVersion());
    }


    public sealed class GetDeployPipelineArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique pipeline identifier.
        /// </summary>
        [Input("deployPipelineId", required: true)]
        public string DeployPipelineId { get; set; } = null!;

        public GetDeployPipelineArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDeployPipelineResult
    {
        /// <summary>
        /// The OCID of the compartment where the pipeline is created.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// List of all artifacts used in the pipeline.
        /// </summary>
        public readonly Outputs.GetDeployPipelineDeployPipelineArtifactsResult DeployPipelineArtifacts;
        /// <summary>
        /// List of all environments used in the pipeline.
        /// </summary>
        public readonly Outputs.GetDeployPipelineDeployPipelineEnvironmentsResult DeployPipelineEnvironments;
        public readonly string DeployPipelineId;
        /// <summary>
        /// Specifies list of parameters present in the deployment pipeline. In case of Update operation, replaces existing parameters list. Merging with existing parameters is not supported.
        /// </summary>
        public readonly Outputs.GetDeployPipelineDeployPipelineParametersResult DeployPipelineParameters;
        /// <summary>
        /// Optional description about the deployment pipeline.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Deployment pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Unique identifier that is immutable on creation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The OCID of a project.
        /// </summary>
        public readonly string ProjectId;
        /// <summary>
        /// The current state of the deployment pipeline.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// Time the deployment pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Time the deployment pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDeployPipelineResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            Outputs.GetDeployPipelineDeployPipelineArtifactsResult deployPipelineArtifacts,

            Outputs.GetDeployPipelineDeployPipelineEnvironmentsResult deployPipelineEnvironments,

            string deployPipelineId,

            Outputs.GetDeployPipelineDeployPipelineParametersResult deployPipelineParameters,

            string description,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            string projectId,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DeployPipelineArtifacts = deployPipelineArtifacts;
            DeployPipelineEnvironments = deployPipelineEnvironments;
            DeployPipelineId = deployPipelineId;
            DeployPipelineParameters = deployPipelineParameters;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            ProjectId = projectId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
