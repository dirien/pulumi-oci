// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetInstanceConfigurationInstanceDetailsLaunchDetailsAgentConfigResult
    {
        /// <summary>
        /// Whether Oracle Cloud Agent can run all the available plugins. This includes the management and monitoring plugins.
        /// </summary>
        public readonly bool AreAllPluginsDisabled;
        /// <summary>
        /// Whether Oracle Cloud Agent can run all the available management plugins. Default value is false (management plugins are enabled).
        /// </summary>
        public readonly bool IsManagementDisabled;
        /// <summary>
        /// Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins. Default value is false (monitoring plugins are enabled).
        /// </summary>
        public readonly bool IsMonitoringDisabled;
        /// <summary>
        /// The configuration of plugins associated with this instance.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInstanceConfigurationInstanceDetailsLaunchDetailsAgentConfigPluginsConfigResult> PluginsConfigs;

        [OutputConstructor]
        private GetInstanceConfigurationInstanceDetailsLaunchDetailsAgentConfigResult(
            bool areAllPluginsDisabled,

            bool isManagementDisabled,

            bool isMonitoringDisabled,

            ImmutableArray<Outputs.GetInstanceConfigurationInstanceDetailsLaunchDetailsAgentConfigPluginsConfigResult> pluginsConfigs)
        {
            AreAllPluginsDisabled = areAllPluginsDisabled;
            IsManagementDisabled = isManagementDisabled;
            IsMonitoringDisabled = isMonitoringDisabled;
            PluginsConfigs = pluginsConfigs;
        }
    }
}
