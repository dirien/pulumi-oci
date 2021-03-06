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
    public sealed class GetClusterNetworksClusterNetworkPlacementConfigurationSecondaryVnicSubnetResult
    {
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The subnet [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the secondary VNIC.
        /// </summary>
        public readonly string SubnetId;

        [OutputConstructor]
        private GetClusterNetworksClusterNetworkPlacementConfigurationSecondaryVnicSubnetResult(
            string displayName,

            string subnetId)
        {
            DisplayName = displayName;
            SubnetId = subnetId;
        }
    }
}
