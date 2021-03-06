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
    public sealed class BlockchainPlatformComponentDetailsPeer
    {
        /// <summary>
        /// Availability Domain of peer
        /// </summary>
        public readonly string? Ad;
        /// <summary>
        /// peer alias
        /// </summary>
        public readonly string? Alias;
        /// <summary>
        /// Host name of VM
        /// </summary>
        public readonly string? Host;
        /// <summary>
        /// OCPU allocation parameter
        /// </summary>
        public readonly Outputs.BlockchainPlatformComponentDetailsPeerOcpuAllocationParam? OcpuAllocationParam;
        /// <summary>
        /// peer identifier
        /// </summary>
        public readonly string? PeerKey;
        /// <summary>
        /// Peer role
        /// </summary>
        public readonly string? Role;
        /// <summary>
        /// The current state of the Platform Instance.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private BlockchainPlatformComponentDetailsPeer(
            string? ad,

            string? alias,

            string? host,

            Outputs.BlockchainPlatformComponentDetailsPeerOcpuAllocationParam? ocpuAllocationParam,

            string? peerKey,

            string? role,

            string? state)
        {
            Ad = ad;
            Alias = alias;
            Host = host;
            OcpuAllocationParam = ocpuAllocationParam;
            PeerKey = peerKey;
            Role = role;
            State = state;
        }
    }
}
