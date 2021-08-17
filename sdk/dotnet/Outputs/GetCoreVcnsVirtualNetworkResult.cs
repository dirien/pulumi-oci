// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Outputs
{

    [OutputType]
    public sealed class GetCoreVcnsVirtualNetworkResult
    {
        /// <summary>
        /// Deprecated. The first CIDR IP address from cidrBlocks.  Example: `172.16.0.0/16`
        /// </summary>
        public readonly string CidrBlock;
        /// <summary>
        /// The list of IPv4 CIDR blocks the VCN will use.
        /// </summary>
        public readonly ImmutableArray<string> CidrBlocks;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The OCID for the VCN's default set of DHCP options.
        /// </summary>
        public readonly string DefaultDhcpOptionsId;
        /// <summary>
        /// The OCID for the VCN's default route table.
        /// </summary>
        public readonly string DefaultRouteTableId;
        /// <summary>
        /// The OCID for the VCN's default security list.
        /// </summary>
        public readonly string DefaultSecurityListId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// A DNS label for the VCN, used in conjunction with the VNIC's hostname and subnet's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance-1.subnet123.vcn1.oraclevcn.com`). Must be an alphanumeric string that begins with a letter. The value cannot be changed.
        /// </summary>
        public readonly string DnsLabel;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The VCN's Oracle ID (OCID).
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// For an IPv6-enabled VCN, this is the list of IPv6 CIDR blocks for the VCN's IP address space. The CIDRs are provided by Oracle and the sizes are always /56.
        /// </summary>
        public readonly ImmutableArray<string> Ipv6cidrBlocks;
        public readonly bool IsIpv6enabled;
        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the VCN was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The VCN's domain name, which consists of the VCN's DNS label, and the `oraclevcn.com` domain.
        /// </summary>
        public readonly string VcnDomainName;

        [OutputConstructor]
        private GetCoreVcnsVirtualNetworkResult(
            string cidrBlock,

            ImmutableArray<string> cidrBlocks,

            string compartmentId,

            string defaultDhcpOptionsId,

            string defaultRouteTableId,

            string defaultSecurityListId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            string dnsLabel,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            ImmutableArray<string> ipv6cidrBlocks,

            bool isIpv6enabled,

            string state,

            string timeCreated,

            string vcnDomainName)
        {
            CidrBlock = cidrBlock;
            CidrBlocks = cidrBlocks;
            CompartmentId = compartmentId;
            DefaultDhcpOptionsId = defaultDhcpOptionsId;
            DefaultRouteTableId = defaultRouteTableId;
            DefaultSecurityListId = defaultSecurityListId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            DnsLabel = dnsLabel;
            FreeformTags = freeformTags;
            Id = id;
            Ipv6cidrBlocks = ipv6cidrBlocks;
            IsIpv6enabled = isIpv6enabled;
            State = state;
            TimeCreated = timeCreated;
            VcnDomainName = vcnDomainName;
        }
    }
}