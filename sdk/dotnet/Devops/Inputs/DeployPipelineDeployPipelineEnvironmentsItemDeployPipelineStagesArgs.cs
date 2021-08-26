// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Devops.Inputs
{

    public sealed class DeployPipelineDeployPipelineEnvironmentsItemDeployPipelineStagesArgs : Pulumi.ResourceArgs
    {
        [Input("items")]
        private InputList<Inputs.DeployPipelineDeployPipelineEnvironmentsItemDeployPipelineStagesItemArgs>? _items;

        /// <summary>
        /// (Updatable) List of parameters defined for a deployment pipeline.
        /// </summary>
        public InputList<Inputs.DeployPipelineDeployPipelineEnvironmentsItemDeployPipelineStagesItemArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.DeployPipelineDeployPipelineEnvironmentsItemDeployPipelineStagesItemArgs>());
            set => _items = value;
        }

        public DeployPipelineDeployPipelineEnvironmentsItemDeployPipelineStagesArgs()
        {
        }
    }
}
