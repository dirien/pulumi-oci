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
    public sealed class BlockchainPlatformComponentDetails
    {
        /// <summary>
        /// List of OSNs
        /// </summary>
        public readonly ImmutableArray<Outputs.BlockchainPlatformComponentDetailsOsn> Osns;
        /// <summary>
        /// List of Peers
        /// </summary>
        public readonly ImmutableArray<Outputs.BlockchainPlatformComponentDetailsPeer> Peers;

        [OutputConstructor]
        private BlockchainPlatformComponentDetails(
            ImmutableArray<Outputs.BlockchainPlatformComponentDetailsOsn> osns,

            ImmutableArray<Outputs.BlockchainPlatformComponentDetailsPeer> peers)
        {
            Osns = osns;
            Peers = peers;
        }
    }
}
