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
    public sealed class GetNetworkLoadBalancersNetworkLoadBalancerCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetNetworkLoadBalancersNetworkLoadBalancerCollectionItemResult> Items;

        [OutputConstructor]
        private GetNetworkLoadBalancersNetworkLoadBalancerCollectionResult(ImmutableArray<Outputs.GetNetworkLoadBalancersNetworkLoadBalancerCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
