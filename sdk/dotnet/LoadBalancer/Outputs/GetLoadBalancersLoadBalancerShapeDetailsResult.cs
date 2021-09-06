// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Outputs
{

    [OutputType]
    public sealed class GetLoadBalancersLoadBalancerShapeDetailsResult
    {
        /// <summary>
        /// Bandwidth in Mbps that determines the maximum bandwidth (ingress plus egress) that the load balancer can achieve. This bandwidth cannot be always guaranteed. For a guaranteed bandwidth use the minimumBandwidthInMbps parameter.
        /// </summary>
        public readonly int MaximumBandwidthInMbps;
        /// <summary>
        /// Bandwidth in Mbps that determines the total pre-provisioned bandwidth (ingress plus egress). The values must be between 0 and the maximumBandwidthInMbps in multiples of 10. The current allowed maximum value is defined in [Service Limits](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/servicelimits.htm).  Example: `150`
        /// </summary>
        public readonly int MinimumBandwidthInMbps;

        [OutputConstructor]
        private GetLoadBalancersLoadBalancerShapeDetailsResult(
            int maximumBandwidthInMbps,

            int minimumBandwidthInMbps)
        {
            MaximumBandwidthInMbps = maximumBandwidthInMbps;
            MinimumBandwidthInMbps = minimumBandwidthInMbps;
        }
    }
}
