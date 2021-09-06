// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Devops
{
    public static class GetDeployStages
    {
        /// <summary>
        /// This data source provides the list of Deploy Stages in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a list of deployment stages.
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
        ///         var testDeployStages = Output.Create(Oci.Devops.GetDeployStages.InvokeAsync(new Oci.Devops.GetDeployStagesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DeployPipelineId = oci_devops_deploy_pipeline.Test_deploy_pipeline.Id,
        ///             DisplayName = @var.Deploy_stage_display_name,
        ///             Id = @var.Deploy_stage_id,
        ///             State = @var.Deploy_stage_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDeployStagesResult> InvokeAsync(GetDeployStagesArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDeployStagesResult>("oci:devops/getDeployStages:getDeployStages", args ?? new GetDeployStagesArgs(), options.WithVersion());
    }


    public sealed class GetDeployStagesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// The ID of the parent pipeline.
        /// </summary>
        [Input("deployPipelineId")]
        public string? DeployPipelineId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDeployStagesFilterArgs>? _filters;
        public List<Inputs.GetDeployStagesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDeployStagesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier or OCID for listing a single resource by ID.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to return only deployment stages that matches the given lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetDeployStagesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDeployStagesResult
    {
        /// <summary>
        /// The OCID of a compartment.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// The OCID of a pipeline.
        /// </summary>
        public readonly string? DeployPipelineId;
        /// <summary>
        /// The list of deploy_stage_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStagesDeployStageCollectionResult> DeployStageCollections;
        /// <summary>
        /// Deployment stage display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDeployStagesFilterResult> Filters;
        /// <summary>
        /// Unique identifier that is immutable on creation.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The current state of the deployment stage.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetDeployStagesResult(
            string? compartmentId,

            string? deployPipelineId,

            ImmutableArray<Outputs.GetDeployStagesDeployStageCollectionResult> deployStageCollections,

            string? displayName,

            ImmutableArray<Outputs.GetDeployStagesFilterResult> filters,

            string? id,

            string? state)
        {
            CompartmentId = compartmentId;
            DeployPipelineId = deployPipelineId;
            DeployStageCollections = deployStageCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
