// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetClusterNetworksClusterNetworkPlacementConfigurationResult
    {
        /// <summary>
        /// The availability domain to place instances.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the primary subnet to place instances.
        /// </summary>
        public readonly string PrimarySubnetId;
        /// <summary>
        /// The set of secondary VNIC data for instances in the pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetClusterNetworksClusterNetworkPlacementConfigurationSecondaryVnicSubnetResult> SecondaryVnicSubnets;

        [OutputConstructor]
        private GetClusterNetworksClusterNetworkPlacementConfigurationResult(
            string availabilityDomain,

            string primarySubnetId,

            ImmutableArray<Outputs.GetClusterNetworksClusterNetworkPlacementConfigurationSecondaryVnicSubnetResult> secondaryVnicSubnets)
        {
            AvailabilityDomain = availabilityDomain;
            PrimarySubnetId = primarySubnetId;
            SecondaryVnicSubnets = secondaryVnicSubnets;
        }
    }
}
