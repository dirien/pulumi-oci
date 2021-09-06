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
    public sealed class BlockchainPlatformComponentDetailsOsn
    {
        /// <summary>
        /// Availability Domain of peer
        /// </summary>
        public readonly string? Ad;
        /// <summary>
        /// OCPU allocation parameter
        /// </summary>
        public readonly Outputs.BlockchainPlatformComponentDetailsOsnOcpuAllocationParam? OcpuAllocationParam;
        /// <summary>
        /// OSN identifier
        /// </summary>
        public readonly string? OsnKey;
        /// <summary>
        /// The current state of the Platform Instance.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private BlockchainPlatformComponentDetailsOsn(
            string? ad,

            Outputs.BlockchainPlatformComponentDetailsOsnOcpuAllocationParam? ocpuAllocationParam,

            string? osnKey,

            string? state)
        {
            Ad = ad;
            OcpuAllocationParam = ocpuAllocationParam;
            OsnKey = osnKey;
            State = state;
        }
    }
}
