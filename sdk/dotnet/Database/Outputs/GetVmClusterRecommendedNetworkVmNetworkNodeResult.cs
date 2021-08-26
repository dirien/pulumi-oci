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
    public sealed class GetVmClusterRecommendedNetworkVmNetworkNodeResult
    {
        /// <summary>
        /// The node host name.
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// The node IP address.
        /// </summary>
        public readonly string Ip;
        /// <summary>
        /// The node virtual IP (VIP) address.
        /// </summary>
        public readonly string Vip;
        /// <summary>
        /// The node virtual IP (VIP) host name.
        /// </summary>
        public readonly string VipHostname;

        [OutputConstructor]
        private GetVmClusterRecommendedNetworkVmNetworkNodeResult(
            string hostname,

            string ip,

            string vip,

            string vipHostname)
        {
            Hostname = hostname;
            Ip = ip;
            Vip = vip;
            VipHostname = vipHostname;
        }
    }
}
