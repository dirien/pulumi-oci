// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class ClusterNetworkPlacementConfigurationGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The availability domain to place instances.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public Input<string> AvailabilityDomain { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the primary subnet to place instances.
        /// </summary>
        [Input("primarySubnetId", required: true)]
        public Input<string> PrimarySubnetId { get; set; } = null!;

        [Input("secondaryVnicSubnets")]
        private InputList<Inputs.ClusterNetworkPlacementConfigurationSecondaryVnicSubnetGetArgs>? _secondaryVnicSubnets;

        /// <summary>
        /// The set of secondary VNIC data for instances in the pool.
        /// </summary>
        public InputList<Inputs.ClusterNetworkPlacementConfigurationSecondaryVnicSubnetGetArgs> SecondaryVnicSubnets
        {
            get => _secondaryVnicSubnets ?? (_secondaryVnicSubnets = new InputList<Inputs.ClusterNetworkPlacementConfigurationSecondaryVnicSubnetGetArgs>());
            set => _secondaryVnicSubnets = value;
        }

        public ClusterNetworkPlacementConfigurationGetArgs()
        {
        }
    }
}
