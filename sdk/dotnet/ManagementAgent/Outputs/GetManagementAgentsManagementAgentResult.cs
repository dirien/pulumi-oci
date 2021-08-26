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
    public sealed class GetManagementAgentsManagementAgentResult
    {
        /// <summary>
        /// The current availability status of managementAgent
        /// </summary>
        public readonly string AvailabilityStatus;
        /// <summary>
        /// The ID of the compartment from which the Management Agents to be listed.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        public readonly ImmutableArray<string> DeployPluginsIds;
        /// <summary>
        /// Filter to return only Management Agents having the particular display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Management Agent host machine name
        /// </summary>
        public readonly string Host;
        /// <summary>
        /// agent identifier
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// agent install key identifier
        /// </summary>
        public readonly string InstallKeyId;
        /// <summary>
        /// Path where Management Agent is installed
        /// </summary>
        public readonly string InstallPath;
        /// <summary>
        /// true if the agent can be upgraded automatically; false if it must be upgraded manually. true is currently unsupported.
        /// </summary>
        public readonly bool IsAgentAutoUpgradable;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        public readonly string ManagedAgentId;
        /// <summary>
        /// Platform Name
        /// </summary>
        public readonly string PlatformName;
        /// <summary>
        /// Filter to return only Management Agents having the particular platform type.
        /// </summary>
        public readonly string PlatformType;
        /// <summary>
        /// Platform Version
        /// </summary>
        public readonly string PlatformVersion;
        /// <summary>
        /// list of managementAgentPlugins associated with the agent
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagementAgentsManagementAgentPluginListResult> PluginLists;
        /// <summary>
        /// Filter to return only Management Agents in the particular lifecycle state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time the Management Agent was created. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the Management Agent has last recorded its health status in telemetry. This value will be null if the agent has not recorded its health status in last 7 days. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeLastHeartbeat;
        /// <summary>
        /// The time the Management Agent was updated. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Filter to return only Management Agents having the particular agent version.
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetManagementAgentsManagementAgentResult(
            string availabilityStatus,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            ImmutableArray<string> deployPluginsIds,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string host,

            string id,

            string installKeyId,

            string installPath,

            bool isAgentAutoUpgradable,

            string lifecycleDetails,

            string managedAgentId,

            string platformName,

            string platformType,

            string platformVersion,

            ImmutableArray<Outputs.GetManagementAgentsManagementAgentPluginListResult> pluginLists,

            string state,

            string timeCreated,

            string timeLastHeartbeat,

            string timeUpdated,

            string version)
        {
            AvailabilityStatus = availabilityStatus;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DeployPluginsIds = deployPluginsIds;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Host = host;
            Id = id;
            InstallKeyId = installKeyId;
            InstallPath = installPath;
            IsAgentAutoUpgradable = isAgentAutoUpgradable;
            LifecycleDetails = lifecycleDetails;
            ManagedAgentId = managedAgentId;
            PlatformName = platformName;
            PlatformType = platformType;
            PlatformVersion = platformVersion;
            PluginLists = pluginLists;
            State = state;
            TimeCreated = timeCreated;
            TimeLastHeartbeat = timeLastHeartbeat;
            TimeUpdated = timeUpdated;
            Version = version;
        }
    }
}