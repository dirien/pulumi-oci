// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstanceAgentConfigPluginsConfigGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Whether the plugin should be enabled or disabled.
        /// </summary>
        [Input("desiredState", required: true)]
        public Input<string> DesiredState { get; set; } = null!;

        /// <summary>
        /// (Updatable) The plugin name. To get a list of available plugins, use the [ListInstanceagentAvailablePlugins](https://docs.cloud.oracle.com/iaas/api/#/en/instanceagent/20180530/Plugin/ListInstanceagentAvailablePlugins) operation in the Oracle Cloud Agent API. For more information about the available plugins, see [Managing Plugins with Oracle Cloud Agent](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/manage-plugins.htm).
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        public InstanceAgentConfigPluginsConfigGetArgs()
        {
        }
    }
}
