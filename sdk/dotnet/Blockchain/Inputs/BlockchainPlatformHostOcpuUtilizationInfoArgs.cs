// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Blockchain.Inputs
{

    public sealed class BlockchainPlatformHostOcpuUtilizationInfoArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Host name of VM
        /// </summary>
        [Input("host")]
        public Input<string>? Host { get; set; }

        /// <summary>
        /// Number of total OCPU capacity on the host
        /// </summary>
        [Input("ocpuCapacityNumber")]
        public Input<double>? OcpuCapacityNumber { get; set; }

        /// <summary>
        /// Number of OCPU utilized
        /// </summary>
        [Input("ocpuUtilizationNumber")]
        public Input<double>? OcpuUtilizationNumber { get; set; }

        public BlockchainPlatformHostOcpuUtilizationInfoArgs()
        {
        }
    }
}
