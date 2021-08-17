// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Outputs
{

    [OutputType]
    public sealed class GetComputeinstanceagentInstanceAgentPluginsInstanceAgentPluginResult
    {
        /// <summary>
        /// The optional message from the agent plugin
        /// </summary>
        public readonly string Message;
        /// <summary>
        /// The plugin name
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The plugin status
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The last update time of the plugin in UTC
        /// </summary>
        public readonly string TimeLastUpdatedUtc;

        [OutputConstructor]
        private GetComputeinstanceagentInstanceAgentPluginsInstanceAgentPluginResult(
            string message,

            string name,

            string status,

            string timeLastUpdatedUtc)
        {
            Message = message;
            Name = name;
            Status = status;
            TimeLastUpdatedUtc = timeLastUpdatedUtc;
        }
    }
}