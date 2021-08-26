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
    public sealed class GetOsnsOsnCollectionItemResult
    {
        /// <summary>
        /// Availability Domain of OSN
        /// </summary>
        public readonly string Ad;
        /// <summary>
        /// Unique service identifier.
        /// </summary>
        public readonly string BlockchainPlatformId;
        /// <summary>
        /// OCPU allocation parameter
        /// </summary>
        public readonly Outputs.GetOsnsOsnCollectionItemOcpuAllocationParamResult OcpuAllocationParam;
        /// <summary>
        /// OSN identifier
        /// </summary>
        public readonly string OsnKey;
        /// <summary>
        /// The current state of the OSN.
        /// </summary>
        public readonly string State;

        [OutputConstructor]
        private GetOsnsOsnCollectionItemResult(
            string ad,

            string blockchainPlatformId,

            Outputs.GetOsnsOsnCollectionItemOcpuAllocationParamResult ocpuAllocationParam,

            string osnKey,

            string state)
        {
            Ad = ad;
            BlockchainPlatformId = blockchainPlatformId;
            OcpuAllocationParam = ocpuAllocationParam;
            OsnKey = osnKey;
            State = state;
        }
    }
}
