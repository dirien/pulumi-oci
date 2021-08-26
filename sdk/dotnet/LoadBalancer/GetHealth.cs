// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer
{
    public static class GetHealth
    {
        /// <summary>
        /// This data source provides details about a specific Load Balancer Health resource in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Gets the health status for the specified load balancer.
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
        ///         var testLoadBalancerHealth = Output.Create(Oci.LoadBalancer.GetHealth.InvokeAsync(new Oci.LoadBalancer.GetHealthArgs
        ///         {
        ///             LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetHealthResult> InvokeAsync(GetHealthArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetHealthResult>("oci:loadbalancer/getHealth:getHealth", args ?? new GetHealthArgs(), options.WithVersion());
    }


    public sealed class GetHealthArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to return health status for.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public string LoadBalancerId { get; set; } = null!;

        public GetHealthArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetHealthResult
    {
        /// <summary>
        /// A list of backend sets that are currently in the `CRITICAL` health state. The list identifies each backend set by the friendly name you assigned when you created it.  Example: `example_backend_set`
        /// </summary>
        public readonly ImmutableArray<string> CriticalStateBackendSetNames;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string LoadBalancerId;
        /// <summary>
        /// The overall health status of the load balancer.
        /// *  **OK:** All backend sets associated with the load balancer return a status of `OK`.
        /// *  **WARNING:** At least one of the backend sets associated with the load balancer returns a status of `WARNING`, no backend sets return a status of `CRITICAL`, and the load balancer life cycle state is `ACTIVE`.
        /// *  **CRITICAL:** One or more of the backend sets associated with the load balancer return a status of `CRITICAL`.
        /// *  **UNKNOWN:** If any one of the following conditions is true:
        /// *  The load balancer life cycle state is not `ACTIVE`.
        /// *  No backend sets are defined for the load balancer.
        /// *  More than half of the backend sets associated with the load balancer return a status of `UNKNOWN`, none of the backend sets return a status of `WARNING` or `CRITICAL`, and the load balancer life cycle state is `ACTIVE`.
        /// *  The system could not retrieve metrics for any reason.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The total number of backend sets associated with this load balancer.  Example: `4`
        /// </summary>
        public readonly int TotalBackendSetCount;
        /// <summary>
        /// A list of backend sets that are currently in the `UNKNOWN` health state. The list identifies each backend set by the friendly name you assigned when you created it.  Example: `example_backend_set2`
        /// </summary>
        public readonly ImmutableArray<string> UnknownStateBackendSetNames;
        /// <summary>
        /// A list of backend sets that are currently in the `WARNING` health state. The list identifies each backend set by the friendly name you assigned when you created it.  Example: `example_backend_set3`
        /// </summary>
        public readonly ImmutableArray<string> WarningStateBackendSetNames;

        [OutputConstructor]
        private GetHealthResult(
            ImmutableArray<string> criticalStateBackendSetNames,

            string id,

            string loadBalancerId,

            string status,

            int totalBackendSetCount,

            ImmutableArray<string> unknownStateBackendSetNames,

            ImmutableArray<string> warningStateBackendSetNames)
        {
            CriticalStateBackendSetNames = criticalStateBackendSetNames;
            Id = id;
            LoadBalancerId = loadBalancerId;
            Status = status;
            TotalBackendSetCount = totalBackendSetCount;
            UnknownStateBackendSetNames = unknownStateBackendSetNames;
            WarningStateBackendSetNames = warningStateBackendSetNames;
        }
    }
}