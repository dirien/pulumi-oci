// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ManagementAgent
{
    public static class GetManagementAgentInstallKey
    {
        /// <summary>
        /// This data source provides details about a specific Management Agent Install Key resource in Oracle Cloud Infrastructure Management Agent service.
        /// 
        /// Gets complete details of the Agent install Key for a given key id
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
        ///         var testManagementAgentInstallKey = Output.Create(Oci.ManagementAgent.GetManagementAgentInstallKey.InvokeAsync(new Oci.ManagementAgent.GetManagementAgentInstallKeyArgs
        ///         {
        ///             ManagementAgentInstallKeyId = oci_management_agent_management_agent_install_key.Test_management_agent_install_key.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetManagementAgentInstallKeyResult> InvokeAsync(GetManagementAgentInstallKeyArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetManagementAgentInstallKeyResult>("oci:managementagent/getManagementAgentInstallKey:getManagementAgentInstallKey", args ?? new GetManagementAgentInstallKeyArgs(), options.WithVersion());
    }


    public sealed class GetManagementAgentInstallKeyArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique Management Agent Install Key identifier
        /// </summary>
        [Input("managementAgentInstallKeyId", required: true)]
        public string ManagementAgentInstallKeyId { get; set; } = null!;

        public GetManagementAgentInstallKeyArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetManagementAgentInstallKeyResult
    {
        /// <summary>
        /// Total number of install for this keys
        /// </summary>
        public readonly int AllowedKeyInstallCount;
        /// <summary>
        /// Compartment Identifier
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Principal id of user who created the Agent Install key
        /// </summary>
        public readonly string CreatedByPrincipalId;
        /// <summary>
        /// Total number of install for this keys
        /// </summary>
        public readonly int CurrentKeyInstallCount;
        /// <summary>
        /// Management Agent Install Key Name
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Agent install Key identifier
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Management Agent Install Key
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        public readonly string ManagementAgentInstallKeyId;
        /// <summary>
        /// Status of Key
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time when Management Agent install Key was created. An RFC3339 formatted date time string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// date after which key would expire after creation
        /// </summary>
        public readonly string TimeExpires;
        /// <summary>
        /// The time when Management Agent install Key was updated. An RFC3339 formatted date time string
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetManagementAgentInstallKeyResult(
            int allowedKeyInstallCount,

            string compartmentId,

            string createdByPrincipalId,

            int currentKeyInstallCount,

            string displayName,

            string id,

            string key,

            string lifecycleDetails,

            string managementAgentInstallKeyId,

            string state,

            string timeCreated,

            string timeExpires,

            string timeUpdated)
        {
            AllowedKeyInstallCount = allowedKeyInstallCount;
            CompartmentId = compartmentId;
            CreatedByPrincipalId = createdByPrincipalId;
            CurrentKeyInstallCount = currentKeyInstallCount;
            DisplayName = displayName;
            Id = id;
            Key = key;
            LifecycleDetails = lifecycleDetails;
            ManagementAgentInstallKeyId = managementAgentInstallKeyId;
            State = state;
            TimeCreated = timeCreated;
            TimeExpires = timeExpires;
            TimeUpdated = timeUpdated;
        }
    }
}
