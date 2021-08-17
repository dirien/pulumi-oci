// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Outputs
{

    [OutputType]
    public sealed class GetDevopsDeploymentDeployPipelineArtifactsItemDeployPipelineStagesResult
    {
        /// <summary>
        /// A list of stage predecessors for a stage.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDevopsDeploymentDeployPipelineArtifactsItemDeployPipelineStagesItemResult> Items;

        [OutputConstructor]
        private GetDevopsDeploymentDeployPipelineArtifactsItemDeployPipelineStagesResult(ImmutableArray<Outputs.GetDevopsDeploymentDeployPipelineArtifactsItemDeployPipelineStagesItemResult> items)
        {
            Items = items;
        }
    }
}