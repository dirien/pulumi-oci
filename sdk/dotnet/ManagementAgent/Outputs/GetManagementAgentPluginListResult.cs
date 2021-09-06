// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ManagementAgent.Outputs
{

    [OutputType]
    public sealed class GetManagementAgentPluginListResult
    {
        /// <summary>
        /// Management Agent Plugin Identifier, can be renamed
        /// </summary>
        public readonly string PluginDisplayName;
        /// <summary>
        /// Plugin Id
        /// </summary>
        public readonly string PluginId;
        /// <summary>
        /// Management Agent Plugin Name
        /// </summary>
        public readonly string PluginName;
        /// <summary>
        /// Plugin Version
        /// </summary>
        public readonly string PluginVersion;

        [OutputConstructor]
        private GetManagementAgentPluginListResult(
            string pluginDisplayName,

            string pluginId,

            string pluginName,

            string pluginVersion)
        {
            PluginDisplayName = pluginDisplayName;
            PluginId = pluginId;
            PluginName = pluginName;
            PluginVersion = pluginVersion;
        }
    }
}
