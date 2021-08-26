// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetVmClusterRecommendedNetworkNetworkResult
    {
        /// <summary>
        /// The cidr for the network.
        /// </summary>
        public readonly string Cidr;
        /// <summary>
        /// The network domain name.
        /// </summary>
        public readonly string Domain;
        /// <summary>
        /// The network gateway.
        /// </summary>
        public readonly string Gateway;
        /// <summary>
        /// The network netmask.
        /// </summary>
        public readonly string Netmask;
        /// <summary>
        /// The network type.
        /// </summary>
        public readonly string NetworkType;
        /// <summary>
        /// The network domain name.
        /// </summary>
        public readonly string Prefix;
        /// <summary>
        /// The network VLAN ID.
        /// </summary>
        public readonly string VlanId;

        [OutputConstructor]
        private GetVmClusterRecommendedNetworkNetworkResult(
            string cidr,

            string domain,

            string gateway,

            string netmask,

            string networkType,

            string prefix,

            string vlanId)
        {
            Cidr = cidr;
            Domain = domain;
            Gateway = gateway;
            Netmask = netmask;
            NetworkType = networkType;
            Prefix = prefix;
            VlanId = vlanId;
        }
    }
}