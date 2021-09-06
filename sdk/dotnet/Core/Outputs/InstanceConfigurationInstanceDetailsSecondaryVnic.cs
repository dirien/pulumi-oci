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
    public sealed class InstanceConfigurationInstanceDetailsSecondaryVnic
    {
        /// <summary>
        /// Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
        /// </summary>
        public readonly Outputs.InstanceConfigurationInstanceDetailsSecondaryVnicCreateVnicDetails? CreateVnicDetails;
        /// <summary>
        /// A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        /// </summary>
        public readonly int? NicIndex;

        [OutputConstructor]
        private InstanceConfigurationInstanceDetailsSecondaryVnic(
            Outputs.InstanceConfigurationInstanceDetailsSecondaryVnicCreateVnicDetails? createVnicDetails,

            string? displayName,

            int? nicIndex)
        {
            CreateVnicDetails = createVnicDetails;
            DisplayName = displayName;
            NicIndex = nicIndex;
        }
    }
}
