// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Devops.Outputs
{

    [OutputType]
    public sealed class DeployPipelineDeployPipelineArtifactsItemDeployPipelineStages
    {
        /// <summary>
        /// (Updatable) List of parameters defined for a deployment pipeline.
        /// </summary>
        public readonly ImmutableArray<Outputs.DeployPipelineDeployPipelineArtifactsItemDeployPipelineStagesItem> Items;

        [OutputConstructor]
        private DeployPipelineDeployPipelineArtifactsItemDeployPipelineStages(ImmutableArray<Outputs.DeployPipelineDeployPipelineArtifactsItemDeployPipelineStagesItem> items)
        {
            Items = items;
        }
    }
}
