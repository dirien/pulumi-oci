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
    public sealed class DeployStageDeployStagePredecessorCollection
    {
        /// <summary>
        /// (Updatable) The IP address of the backend server. A server could be a compute instance or a load balancer.
        /// </summary>
        public readonly ImmutableArray<Outputs.DeployStageDeployStagePredecessorCollectionItem> Items;

        [OutputConstructor]
        private DeployStageDeployStagePredecessorCollection(ImmutableArray<Outputs.DeployStageDeployStagePredecessorCollectionItem> items)
        {
            Items = items;
        }
    }
}
