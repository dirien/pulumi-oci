// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer.Outputs
{

    [OutputType]
    public sealed class GetNetworkLoadBalancerIpAddressResult
    {
        /// <summary>
        /// An IP address.  Example: `192.168.0.3`
        /// </summary>
        public readonly string IpAddress;
        /// <summary>
        /// Whether the IP address is public or private.
        /// </summary>
        public readonly bool IsPublic;
        /// <summary>
        /// An object representing a reserved IP address to be attached or that is already attached to a network load balancer.
        /// </summary>
        public readonly Outputs.GetNetworkLoadBalancerIpAddressReservedIpResult ReservedIp;

        [OutputConstructor]
        private GetNetworkLoadBalancerIpAddressResult(
            string ipAddress,

            bool isPublic,

            Outputs.GetNetworkLoadBalancerIpAddressReservedIpResult reservedIp)
        {
            IpAddress = ipAddress;
            IsPublic = isPublic;
            ReservedIp = reservedIp;
        }
    }
}
