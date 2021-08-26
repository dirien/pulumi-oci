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
    public sealed class InstanceConfigurationInstanceDetailsSecondaryVnicCreateVnicDetails
    {
        /// <summary>
        /// Whether the VNIC should be assigned a private DNS record. See the `assignPrivateDnsRecord` attribute of [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/CreateVnicDetails/) for more information.
        /// </summary>
        public readonly bool? AssignPrivateDnsRecord;
        /// <summary>
        /// Whether the VNIC should be assigned a public IP address. See the `assignPublicIp` attribute of [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) for more information.
        /// </summary>
        public readonly bool? AssignPublicIp;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object>? DefinedTags;
        /// <summary>
        /// A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object>? FreeformTags;
        /// <summary>
        /// The hostname for the VNIC's primary private IP. See the `hostnameLabel` attribute of [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) for more information.
        /// </summary>
        public readonly string? HostnameLabel;
        /// <summary>
        /// A list of the OCIDs of the network security groups (NSGs) to add the VNIC to. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/).
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// A private IP address of your choice to assign to the VNIC. See the `privateIp` attribute of [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) for more information.
        /// </summary>
        public readonly string? PrivateIp;
        /// <summary>
        /// Whether the source/destination check is disabled on the VNIC. See the `skipSourceDestCheck` attribute of [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) for more information.
        /// </summary>
        public readonly bool? SkipSourceDestCheck;
        /// <summary>
        /// The OCID of the subnet to create the VNIC in. See the `subnetId` attribute of [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) for more information.
        /// </summary>
        public readonly string? SubnetId;

        [OutputConstructor]
        private InstanceConfigurationInstanceDetailsSecondaryVnicCreateVnicDetails(
            bool? assignPrivateDnsRecord,

            bool? assignPublicIp,

            ImmutableDictionary<string, object>? definedTags,

            string? displayName,

            ImmutableDictionary<string, object>? freeformTags,

            string? hostnameLabel,

            ImmutableArray<string> nsgIds,

            string? privateIp,

            bool? skipSourceDestCheck,

            string? subnetId)
        {
            AssignPrivateDnsRecord = assignPrivateDnsRecord;
            AssignPublicIp = assignPublicIp;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            HostnameLabel = hostnameLabel;
            NsgIds = nsgIds;
            PrivateIp = privateIp;
            SkipSourceDestCheck = skipSourceDestCheck;
            SubnetId = subnetId;
        }
    }
}
