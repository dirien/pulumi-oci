// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ComputeInstanceAgent
{
    public static class GetInstanceAgentPlugin
    {
        /// <summary>
        /// This data source provides details about a specific Instance Agent Plugin resource in Oracle Cloud Infrastructure Compute Instance Agent service.
        /// 
        /// The API to get information for a plugin.
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
        ///         var testInstanceAgentPlugin = Output.Create(Oci.ComputeInstanceAgent.GetInstanceAgentPlugin.InvokeAsync(new Oci.ComputeInstanceAgent.GetInstanceAgentPluginArgs
        ///         {
        ///             InstanceagentId = oci_computeinstanceagent_instanceagent.Test_instanceagent.Id,
        ///             PluginName = @var.Instance_agent_plugin_plugin_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetInstanceAgentPluginResult> InvokeAsync(GetInstanceAgentPluginArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetInstanceAgentPluginResult>("oci:computeinstanceagent/getInstanceAgentPlugin:getInstanceAgentPlugin", args ?? new GetInstanceAgentPluginArgs(), options.WithVersion());
    }


    public sealed class GetInstanceAgentPluginArgs : Pulumi.InvokeArgs
    {
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The OCID of the instance.
        /// </summary>
        [Input("instanceagentId", required: true)]
        public string InstanceagentId { get; set; } = null!;

        /// <summary>
        /// The name of the plugin.
        /// </summary>
        [Input("pluginName", required: true)]
        public string PluginName { get; set; } = null!;

        public GetInstanceAgentPluginArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetInstanceAgentPluginResult
    {
        public readonly string CompartmentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string InstanceagentId;
        /// <summary>
        /// The optional message from the agent plugin
        /// </summary>
        public readonly string Message;
        /// <summary>
        /// The plugin name
        /// </summary>
        public readonly string Name;
        public readonly string PluginName;
        /// <summary>
        /// The plugin status Specified the plugin state on the instance * `RUNNING` - The plugin is in running state * `STOPPED` - The plugin is in stopped state * `NOT_SUPPORTED` - The plugin is not supported on this platform * `INVALID` - The plugin state is not recognizable by the service
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The last update time of the plugin in UTC
        /// </summary>
        public readonly string TimeLastUpdatedUtc;

        [OutputConstructor]
        private GetInstanceAgentPluginResult(
            string compartmentId,

            string id,

            string instanceagentId,

            string message,

            string name,

            string pluginName,

            string status,

            string timeLastUpdatedUtc)
        {
            CompartmentId = compartmentId;
            Id = id;
            InstanceagentId = instanceagentId;
            Message = message;
            Name = name;
            PluginName = pluginName;
            Status = status;
            TimeLastUpdatedUtc = timeLastUpdatedUtc;
        }
    }
}
