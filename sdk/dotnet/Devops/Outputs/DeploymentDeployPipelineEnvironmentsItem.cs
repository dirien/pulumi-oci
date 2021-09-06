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
    public sealed class DeploymentDeployPipelineEnvironmentsItem
    {
        /// <summary>
        /// The OCID of an Environment
        /// </summary>
        public readonly string? DeployEnvironmentId;
        /// <summary>
        /// List of stages.
        /// </summary>
        public readonly Outputs.DeploymentDeployPipelineEnvironmentsItemDeployPipelineStages? DeployPipelineStages;
        /// <summary>
        /// (Updatable) Deployment display name. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;

        [OutputConstructor]
        private DeploymentDeployPipelineEnvironmentsItem(
            string? deployEnvironmentId,

            Outputs.DeploymentDeployPipelineEnvironmentsItemDeployPipelineStages? deployPipelineStages,

            string? displayName)
        {
            DeployEnvironmentId = deployEnvironmentId;
            DeployPipelineStages = deployPipelineStages;
            DisplayName = displayName;
        }
    }
}
