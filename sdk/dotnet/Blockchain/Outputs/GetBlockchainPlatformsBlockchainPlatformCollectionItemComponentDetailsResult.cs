// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Blockchain.Outputs
{

    [OutputType]
    public sealed class GetBlockchainPlatformsBlockchainPlatformCollectionItemComponentDetailsResult
    {
        /// <summary>
        /// List of OSNs
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBlockchainPlatformsBlockchainPlatformCollectionItemComponentDetailsOsnResult> Osns;
        /// <summary>
        /// List of Peers
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBlockchainPlatformsBlockchainPlatformCollectionItemComponentDetailsPeerResult> Peers;

        [OutputConstructor]
        private GetBlockchainPlatformsBlockchainPlatformCollectionItemComponentDetailsResult(
            ImmutableArray<Outputs.GetBlockchainPlatformsBlockchainPlatformCollectionItemComponentDetailsOsnResult> osns,

            ImmutableArray<Outputs.GetBlockchainPlatformsBlockchainPlatformCollectionItemComponentDetailsPeerResult> peers)
        {
            Osns = osns;
            Peers = peers;
        }
    }
}
