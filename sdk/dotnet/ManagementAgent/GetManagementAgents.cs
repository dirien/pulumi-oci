// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ManagementAgent
{
    public static class GetManagementAgents
    {
        /// <summary>
        /// This data source provides the list of Management Agents in Oracle Cloud Infrastructure Management Agent service.
        /// 
        /// Returns a list of Management Agent.
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
        ///         var testManagementAgents = Output.Create(Oci.ManagementAgent.GetManagementAgents.InvokeAsync(new Oci.ManagementAgent.GetManagementAgentsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Management_agent_display_name,
        ///             PlatformType = @var.Management_agent_platform_type,
        ///             PluginName = @var.Management_agent_plugin_name,
        ///             State = @var.Management_agent_state,
        ///             Version = @var.Management_agent_version,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetManagementAgentsResult> InvokeAsync(GetManagementAgentsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetManagementAgentsResult>("oci:managementagent/getManagementAgents:getManagementAgents", args ?? new GetManagementAgentsArgs(), options.WithVersion());
    }


    public sealed class GetManagementAgentsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment from which the Management Agents to be listed.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Filter to return only Management Agents having the particular display name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetManagementAgentsFilterArgs>? _filters;
        public List<Inputs.GetManagementAgentsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagementAgentsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Filter to return only Management Agents in the particular lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetManagementAgentsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetManagementAgentsResult
    {
        /// <summary>
        /// Compartment Identifier
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Management Agent Name
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetManagementAgentsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of management_agents.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagementAgentsManagementAgentResult> ManagementAgents;
        /// <summary>
        /// The current state of managementAgent
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetManagementAgentsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetManagementAgentsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetManagementAgentsManagementAgentResult> managementAgents,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            ManagementAgents = managementAgents;
            State = state;
        }
    }
}
