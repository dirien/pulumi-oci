// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer
{
    public static class GetNetworkLoadBalancerHealth
    {
        /// <summary>
        /// This data source provides details about a specific Network Load Balancer Health resource in Oracle Cloud Infrastructure Network Load Balancer service.
        /// 
        /// Retrieves the health status for the specified network load balancer.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testNetworkLoadBalancerHealth = Output.Create(Oci.NetworkLoadBalancer.GetNetworkLoadBalancerHealth.InvokeAsync(new Oci.NetworkLoadBalancer.GetNetworkLoadBalancerHealthArgs
        ///         {
        ///             NetworkLoadBalancerId = oci_network_load_balancer_network_load_balancer.Test_network_load_balancer.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetNetworkLoadBalancerHealthResult> InvokeAsync(GetNetworkLoadBalancerHealthArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetNetworkLoadBalancerHealthResult>("oci:networkloadbalancer/getNetworkLoadBalancerHealth:getNetworkLoadBalancerHealth", args ?? new GetNetworkLoadBalancerHealthArgs(), options.WithVersion());
    }


    public sealed class GetNetworkLoadBalancerHealthArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Input("networkLoadBalancerId", required: true)]
        public string NetworkLoadBalancerId { get; set; } = null!;

        public GetNetworkLoadBalancerHealthArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetNetworkLoadBalancerHealthResult
    {
        /// <summary>
        /// A list of backend sets that are currently in the `CRITICAL` health state. The list identifies each backend set by the user-friendly name you assigned when you created the backend set.  Example: `example_backend_set`
        /// </summary>
        public readonly ImmutableArray<string> CriticalStateBackendSetNames;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string NetworkLoadBalancerId;
        /// <summary>
        /// The overall health status of the network load balancer.
        /// *  **OK:** All backend sets associated with the network load balancer return a status of `OK`.
        /// *  **WARNING:** At least one of the backend sets associated with the network load balancer returns a status of `WARNING`, no backend sets return a status of `CRITICAL`, and the network load balancer life cycle state is `ACTIVE`.
        /// *  **CRITICAL:** One or more of the backend sets associated with the network load balancer return a status of `CRITICAL`.
        /// *  **UNKNOWN:** If any one of the following conditions is true:
        /// *  The network load balancer life cycle state is not `ACTIVE`.
        /// *  No backend sets are defined for the network load balancer.
        /// *  More than half of the backend sets associated with the network load balancer return a status of `UNKNOWN`, none of the backend sets return a status of `WARNING` or `CRITICAL`, and the network load balancer life cycle state is `ACTIVE`.
        /// *  The system could not retrieve metrics for any reason.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The total number of backend sets associated with this network load balancer.  Example: `4`
        /// </summary>
        public readonly int TotalBackendSetCount;
        /// <summary>
        /// A list of backend sets that are currently in the `UNKNOWN` health state. The list identifies each backend set by the user-friendly name you assigned when you created the backend set.  Example: `example_backend_set2`
        /// </summary>
        public readonly ImmutableArray<string> UnknownStateBackendSetNames;
        /// <summary>
        /// A list of backend sets that are currently in the `WARNING` health state. The list identifies each backend set by the user-friendly name you assigned when you created the backend set.  Example: `example_backend_set3`
        /// </summary>
        public readonly ImmutableArray<string> WarningStateBackendSetNames;

        [OutputConstructor]
        private GetNetworkLoadBalancerHealthResult(
            ImmutableArray<string> criticalStateBackendSetNames,

            string id,

            string networkLoadBalancerId,

            string status,

            int totalBackendSetCount,

            ImmutableArray<string> unknownStateBackendSetNames,

            ImmutableArray<string> warningStateBackendSetNames)
        {
            CriticalStateBackendSetNames = criticalStateBackendSetNames;
            Id = id;
            NetworkLoadBalancerId = networkLoadBalancerId;
            Status = status;
            TotalBackendSetCount = totalBackendSetCount;
            UnknownStateBackendSetNames = unknownStateBackendSetNames;
            WarningStateBackendSetNames = warningStateBackendSetNames;
        }
    }
}
