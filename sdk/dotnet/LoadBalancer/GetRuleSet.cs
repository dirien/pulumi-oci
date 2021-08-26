// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer
{
    public static class GetRuleSet
    {
        /// <summary>
        /// This data source provides details about a specific Rule Set resource in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Gets the specified set of rules.
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
        ///         var testRuleSet = Output.Create(Oci.LoadBalancer.GetRuleSet.InvokeAsync(new Oci.LoadBalancer.GetRuleSetArgs
        ///         {
        ///             LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
        ///             Name = @var.Rule_set_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetRuleSetResult> InvokeAsync(GetRuleSetArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetRuleSetResult>("oci:loadbalancer/getRuleSet:getRuleSet", args ?? new GetRuleSetArgs(), options.WithVersion());
    }


    public sealed class GetRuleSetArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public string LoadBalancerId { get; set; } = null!;

        /// <summary>
        /// The name of the rule set to retrieve.  Example: `example_rule_set`
        /// </summary>
        [Input("name", required: true)]
        public string Name { get; set; } = null!;

        public GetRuleSetArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetRuleSetResult
    {
        public readonly string Id;
        /// <summary>
        /// An array of rules that compose the rule set.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRuleSetItemResult> Items;
        public readonly string LoadBalancerId;
        /// <summary>
        /// The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_rule_set`
        /// </summary>
        public readonly string Name;
        public readonly string State;

        [OutputConstructor]
        private GetRuleSetResult(
            string id,

            ImmutableArray<Outputs.GetRuleSetItemResult> items,

            string loadBalancerId,

            string name,

            string state)
        {
            Id = id;
            Items = items;
            LoadBalancerId = loadBalancerId;
            Name = name;
            State = state;
        }
    }
}
