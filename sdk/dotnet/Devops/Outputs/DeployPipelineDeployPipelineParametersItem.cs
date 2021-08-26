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
    public sealed class DeployPipelineDeployPipelineParametersItem
    {
        /// <summary>
        /// (Updatable) Default value of the parameter.
        /// </summary>
        public readonly string? DefaultValue;
        /// <summary>
        /// (Updatable) Optional description about the deployment pipeline.
        /// </summary>
        public readonly string? Description;
        /// <summary>
        /// (Updatable) Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$.
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private DeployPipelineDeployPipelineParametersItem(
            string? defaultValue,

            string? description,

            string name)
        {
            DefaultValue = defaultValue;
            Description = description;
            Name = name;
        }
    }
}
