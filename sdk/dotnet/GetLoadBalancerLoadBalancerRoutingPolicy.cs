// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetLoadBalancerLoadBalancerRoutingPolicy
    {
        /// <summary>
        /// This data source provides details about a specific Load Balancer Routing Policy resource in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Gets the specified routing policy.
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
        ///         var testLoadBalancerRoutingPolicy = Output.Create(Oci.GetLoadBalancerLoadBalancerRoutingPolicy.InvokeAsync(new Oci.GetLoadBalancerLoadBalancerRoutingPolicyArgs
        ///         {
        ///             LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
        ///             RoutingPolicyName = oci_load_balancer_routing_policy.Test_routing_policy.Name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetLoadBalancerLoadBalancerRoutingPolicyResult> InvokeAsync(GetLoadBalancerLoadBalancerRoutingPolicyArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetLoadBalancerLoadBalancerRoutingPolicyResult>("oci:index/getLoadBalancerLoadBalancerRoutingPolicy:GetLoadBalancerLoadBalancerRoutingPolicy", args ?? new GetLoadBalancerLoadBalancerRoutingPolicyArgs(), options.WithVersion());
    }


    public sealed class GetLoadBalancerLoadBalancerRoutingPolicyArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public string LoadBalancerId { get; set; } = null!;

        /// <summary>
        /// The name of the routing policy to retrieve.  Example: `example_routing_policy`
        /// </summary>
        [Input("routingPolicyName", required: true)]
        public string RoutingPolicyName { get; set; } = null!;

        public GetLoadBalancerLoadBalancerRoutingPolicyArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetLoadBalancerLoadBalancerRoutingPolicyResult
    {
        /// <summary>
        /// The version of the language in which `condition` of `rules` are composed.
        /// </summary>
        public readonly string ConditionLanguageVersion;
        public readonly string Id;
        public readonly string LoadBalancerId;
        /// <summary>
        /// A unique name for the routing policy rule. Avoid entering confidential information.
        /// </summary>
        public readonly string Name;
        public readonly string RoutingPolicyName;
        /// <summary>
        /// The ordered list of routing rules.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLoadBalancerLoadBalancerRoutingPolicyRuleResult> Rules;
        public readonly string State;

        [OutputConstructor]
        private GetLoadBalancerLoadBalancerRoutingPolicyResult(
            string conditionLanguageVersion,

            string id,

            string loadBalancerId,

            string name,

            string routingPolicyName,

            ImmutableArray<Outputs.GetLoadBalancerLoadBalancerRoutingPolicyRuleResult> rules,

            string state)
        {
            ConditionLanguageVersion = conditionLanguageVersion;
            Id = id;
            LoadBalancerId = loadBalancerId;
            Name = name;
            RoutingPolicyName = routingPolicyName;
            Rules = rules;
            State = state;
        }
    }
}