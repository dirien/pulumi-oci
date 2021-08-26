// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetNetworkSecurityGroupSecurityRules
    {
        /// <summary>
        /// This data source provides the list of Network Security Group Security Rules in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the security rules in the specified network security group.
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
        ///         var testNetworkSecurityGroupSecurityRules = Output.Create(Oci.Core.GetNetworkSecurityGroupSecurityRules.InvokeAsync(new Oci.Core.GetNetworkSecurityGroupSecurityRulesArgs
        ///         {
        ///             NetworkSecurityGroupId = oci_core_network_security_group.Test_network_security_group.Id,
        ///             Direction = @var.Network_security_group_security_rule_direction,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetNetworkSecurityGroupSecurityRulesResult> InvokeAsync(GetNetworkSecurityGroupSecurityRulesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetNetworkSecurityGroupSecurityRulesResult>("oci:core/getNetworkSecurityGroupSecurityRules:getNetworkSecurityGroupSecurityRules", args ?? new GetNetworkSecurityGroupSecurityRulesArgs(), options.WithVersion());
    }


    public sealed class GetNetworkSecurityGroupSecurityRulesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Direction of the security rule. Set to `EGRESS` for rules that allow outbound IP packets, or `INGRESS` for rules that allow inbound IP packets.
        /// </summary>
        [Input("direction")]
        public string? Direction { get; set; }

        [Input("filters")]
        private List<Inputs.GetNetworkSecurityGroupSecurityRulesFilterArgs>? _filters;
        public List<Inputs.GetNetworkSecurityGroupSecurityRulesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNetworkSecurityGroupSecurityRulesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
        /// </summary>
        [Input("networkSecurityGroupId", required: true)]
        public string NetworkSecurityGroupId { get; set; } = null!;

        public GetNetworkSecurityGroupSecurityRulesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetNetworkSecurityGroupSecurityRulesResult
    {
        /// <summary>
        /// Direction of the security rule. Set to `EGRESS` for rules to allow outbound IP packets, or `INGRESS` for rules to allow inbound IP packets.
        /// </summary>
        public readonly string? Direction;
        public readonly ImmutableArray<Outputs.GetNetworkSecurityGroupSecurityRulesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string NetworkSecurityGroupId;
        /// <summary>
        /// The list of security_rules.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleResult> SecurityRules;

        [OutputConstructor]
        private GetNetworkSecurityGroupSecurityRulesResult(
            string? direction,

            ImmutableArray<Outputs.GetNetworkSecurityGroupSecurityRulesFilterResult> filters,

            string id,

            string networkSecurityGroupId,

            ImmutableArray<Outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleResult> securityRules)
        {
            Direction = direction;
            Filters = filters;
            Id = id;
            NetworkSecurityGroupId = networkSecurityGroupId;
            SecurityRules = securityRules;
        }
    }
}
