// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Blockchain.Inputs
{

    public sealed class BlockchainPlatformComponentDetailsOsnArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Availability Domain of peer
        /// </summary>
        [Input("ad")]
        public Input<string>? Ad { get; set; }

        /// <summary>
        /// OCPU allocation parameter
        /// </summary>
        [Input("ocpuAllocationParam")]
        public Input<Inputs.BlockchainPlatformComponentDetailsOsnOcpuAllocationParamArgs>? OcpuAllocationParam { get; set; }

        /// <summary>
        /// OSN identifier
        /// </summary>
        [Input("osnKey")]
        public Input<string>? OsnKey { get; set; }

        /// <summary>
        /// The current state of the Platform Instance.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public BlockchainPlatformComponentDetailsOsnArgs()
        {
        }
    }
}
