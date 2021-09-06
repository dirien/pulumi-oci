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
    public sealed class GetBlockchainPlatformComponentDetailsPeerOcpuAllocationParamResult
    {
        /// <summary>
        /// Number of OCPU allocation
        /// </summary>
        public readonly double OcpuAllocationNumber;

        [OutputConstructor]
        private GetBlockchainPlatformComponentDetailsPeerOcpuAllocationParamResult(double ocpuAllocationNumber)
        {
            OcpuAllocationNumber = ocpuAllocationNumber;
        }
    }
}
