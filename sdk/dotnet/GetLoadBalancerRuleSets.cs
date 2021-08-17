// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetLoadBalancerRuleSets
    {
        /// <summary>
        /// This data source provides the list of Rule Sets in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Lists all rule sets associated with the specified load balancer.
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
        ///         var testRuleSets = Output.Create(Oci.GetLoadBalancerRuleSets.InvokeAsync(new Oci.GetLoadBalancerRuleSetsArgs
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
        public static Task<GetLoadBalancerRuleSetsResult> InvokeAsync(GetLoadBalancerRuleSetsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetLoadBalancerRuleSetsResult>("oci:index/getLoadBalancerRuleSets:GetLoadBalancerRuleSets", args ?? new GetLoadBalancerRuleSetsArgs(), options.WithVersion());
    }


    public sealed class GetLoadBalancerRuleSetsArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetLoadBalancerRuleSetsFilterArgs>? _filters;
        public List<Inputs.GetLoadBalancerRuleSetsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetLoadBalancerRuleSetsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public string LoadBalancerId { get; set; } = null!;

        public GetLoadBalancerRuleSetsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetLoadBalancerRuleSetsResult
    {
        public readonly ImmutableArray<Outputs.GetLoadBalancerRuleSetsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string LoadBalancerId;
        /// <summary>
        /// The list of rule_sets.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLoadBalancerRuleSetsRuleSetResult> RuleSets;

        [OutputConstructor]
        private GetLoadBalancerRuleSetsResult(
            ImmutableArray<Outputs.GetLoadBalancerRuleSetsFilterResult> filters,

            string id,

            string loadBalancerId,

            ImmutableArray<Outputs.GetLoadBalancerRuleSetsRuleSetResult> ruleSets)
        {
            Filters = filters;
            Id = id;
            LoadBalancerId = loadBalancerId;
            RuleSets = ruleSets;
        }
    }
}