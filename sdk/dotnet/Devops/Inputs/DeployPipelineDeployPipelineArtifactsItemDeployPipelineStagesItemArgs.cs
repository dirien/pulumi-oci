// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Devops.Inputs
{

    public sealed class DeployPipelineDeployPipelineArtifactsItemDeployPipelineStagesItemArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of a stage
        /// </summary>
        [Input("deployStageId")]
        public Input<string>? DeployStageId { get; set; }

        /// <summary>
        /// (Updatable) Deployment pipeline display name. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        public DeployPipelineDeployPipelineArtifactsItemDeployPipelineStagesItemArgs()
        {
        }
    }
}
