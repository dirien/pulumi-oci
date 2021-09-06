// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class NodePoolNodeConfigDetailsPlacementConfigGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The availability domain in which to place nodes. Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public Input<string> AvailabilityDomain { get; set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the subnet in which to place nodes.
        /// </summary>
        [Input("subnetId", required: true)]
        public Input<string> SubnetId { get; set; } = null!;

        public NodePoolNodeConfigDetailsPlacementConfigGetArgs()
        {
        }
    }
}
