// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetLoadBalancerListenerRules
    {
        /// <summary>
        /// This data source provides the list of Listener Rules in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Lists all of the rules from all of the rule sets associated with the specified listener. The response organizes
        /// the rules in the following order:
        /// 
        /// *  Access control rules
        /// *  Allow method rules
        /// *  Request header rules
        /// *  Response header rules
        /// 
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
        ///         var testListenerRules = Output.Create(Oci.GetLoadBalancerListenerRules.InvokeAsync(new Oci.GetLoadBalancerListenerRulesArgs
        ///         {
        ///             ListenerName = oci_load_balancer_listener.Test_listener.Name,
        ///             LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetLoadBalancerListenerRulesResult> InvokeAsync(GetLoadBalancerListenerRulesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetLoadBalancerListenerRulesResult>("oci:index/getLoadBalancerListenerRules:GetLoadBalancerListenerRules", args ?? new GetLoadBalancerListenerRulesArgs(), options.WithVersion());
    }


    public sealed class GetLoadBalancerListenerRulesArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetLoadBalancerListenerRulesFilterArgs>? _filters;
        public List<Inputs.GetLoadBalancerListenerRulesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetLoadBalancerListenerRulesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The name of the listener the rules are associated with.
        /// </summary>
        [Input("listenerName", required: true)]
        public string ListenerName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the listener.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public string LoadBalancerId { get; set; } = null!;

        public GetLoadBalancerListenerRulesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetLoadBalancerListenerRulesResult
    {
        public readonly ImmutableArray<Outputs.GetLoadBalancerListenerRulesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string ListenerName;
        /// <summary>
        /// The list of listener_rules.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLoadBalancerListenerRulesListenerRuleResult> ListenerRules;
        public readonly string LoadBalancerId;

        [OutputConstructor]
        private GetLoadBalancerListenerRulesResult(
            ImmutableArray<Outputs.GetLoadBalancerListenerRulesFilterResult> filters,

            string id,

            string listenerName,

            ImmutableArray<Outputs.GetLoadBalancerListenerRulesListenerRuleResult> listenerRules,

            string loadBalancerId)
        {
            Filters = filters;
            Id = id;
            ListenerName = listenerName;
            ListenerRules = listenerRules;
            LoadBalancerId = loadBalancerId;
        }
    }
}