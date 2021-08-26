// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer
{
    public static class GetBackendSet
    {
        /// <summary>
        /// This data source provides details about a specific Backend Set resource in Oracle Cloud Infrastructure Network Load Balancer service.
        /// 
        /// Retrieves the configuration information for the specified backend set.
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
        ///         var testBackendSet = Output.Create(Oci.NetworkLoadBalancer.GetBackendSet.InvokeAsync(new Oci.NetworkLoadBalancer.GetBackendSetArgs
        ///         {
        ///             BackendSetName = oci_network_load_balancer_backend_set.Test_backend_set.Name,
        ///             NetworkLoadBalancerId = oci_network_load_balancer_network_load_balancer.Test_network_load_balancer.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetBackendSetResult> InvokeAsync(GetBackendSetArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetBackendSetResult>("oci:networkloadbalancer/getBackendSet:getBackendSet", args ?? new GetBackendSetArgs(), options.WithVersion());
    }


    public sealed class GetBackendSetArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the backend set to retrieve.  Example: `example_backend_set`
        /// </summary>
        [Input("backendSetName", required: true)]
        public string BackendSetName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Input("networkLoadBalancerId", required: true)]
        public string NetworkLoadBalancerId { get; set; } = null!;

        public GetBackendSetArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetBackendSetResult
    {
        public readonly string BackendSetName;
        /// <summary>
        /// Array of backends.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBackendSetBackendResult> Backends;
        /// <summary>
        /// The health check policy configuration. For more information, see [Editing Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/editinghealthcheck.htm).
        /// </summary>
        public readonly Outputs.GetBackendSetHealthCheckerResult HealthChecker;
        public readonly string Id;
        /// <summary>
        /// If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
        /// </summary>
        public readonly bool IsPreserveSource;
        /// <summary>
        /// A user-friendly name for the backend set that must be unique and cannot be changed.
        /// </summary>
        public readonly string Name;
        public readonly string NetworkLoadBalancerId;
        /// <summary>
        /// The network load balancer policy for the backend set.  Example: `FIVE_TUPLE`
        /// </summary>
        public readonly string Policy;

        [OutputConstructor]
        private GetBackendSetResult(
            string backendSetName,

            ImmutableArray<Outputs.GetBackendSetBackendResult> backends,

            Outputs.GetBackendSetHealthCheckerResult healthChecker,

            string id,

            bool isPreserveSource,

            string name,

            string networkLoadBalancerId,

            string policy)
        {
            BackendSetName = backendSetName;
            Backends = backends;
            HealthChecker = healthChecker;
            Id = id;
            IsPreserveSource = isPreserveSource;
            Name = name;
            NetworkLoadBalancerId = networkLoadBalancerId;
            Policy = policy;
        }
    }
}
