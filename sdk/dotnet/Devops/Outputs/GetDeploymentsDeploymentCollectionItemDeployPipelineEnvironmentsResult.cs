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
    public sealed class GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentsResult
    {
        /// <summary>
        /// A list of stage predecessors for a stage.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentsItemResult> Items;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentsResult(ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentsItemResult> items)
        {
            Items = items;
        }
    }
}
