// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging
{
    public static class GetUnifiedAgentConfiguration
    {
        /// <summary>
        /// This data source provides details about a specific Unified Agent Configuration resource in Oracle Cloud Infrastructure Logging service.
        /// 
        /// Get the unified agent configuration for an ID.
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
        ///         var testUnifiedAgentConfiguration = Output.Create(Oci.Logging.GetUnifiedAgentConfiguration.InvokeAsync(new Oci.Logging.GetUnifiedAgentConfigurationArgs
        ///         {
        ///             UnifiedAgentConfigurationId = oci_logging_unified_agent_configuration.Test_unified_agent_configuration.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetUnifiedAgentConfigurationResult> InvokeAsync(GetUnifiedAgentConfigurationArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetUnifiedAgentConfigurationResult>("oci:logging/getUnifiedAgentConfiguration:getUnifiedAgentConfiguration", args ?? new GetUnifiedAgentConfigurationArgs(), options.WithVersion());
    }


    public sealed class GetUnifiedAgentConfigurationArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the Unified Agent configuration.
        /// </summary>
        [Input("unifiedAgentConfigurationId", required: true)]
        public string UnifiedAgentConfigurationId { get; set; } = null!;

        public GetUnifiedAgentConfigurationArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetUnifiedAgentConfigurationResult
    {
        /// <summary>
        /// The OCID of the compartment that the resource belongs to.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// State of unified agent service configuration.
        /// </summary>
        public readonly string ConfigurationState;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Description for this resource.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Groups using the configuration.
        /// </summary>
        public readonly Outputs.GetUnifiedAgentConfigurationGroupAssociationResult GroupAssociation;
        /// <summary>
        /// The OCID of the resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Whether or not this resource is currently enabled.
        /// </summary>
        public readonly bool IsEnabled;
        /// <summary>
        /// Top level Unified Agent service configuration object.
        /// </summary>
        public readonly Outputs.GetUnifiedAgentConfigurationServiceConfigurationResult ServiceConfiguration;
        /// <summary>
        /// The pipeline state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Time the resource was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Time the resource was last modified.
        /// </summary>
        public readonly string TimeLastModified;
        public readonly string UnifiedAgentConfigurationId;

        [OutputConstructor]
        private GetUnifiedAgentConfigurationResult(
            string compartmentId,

            string configurationState,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            Outputs.GetUnifiedAgentConfigurationGroupAssociationResult groupAssociation,

            string id,

            bool isEnabled,

            Outputs.GetUnifiedAgentConfigurationServiceConfigurationResult serviceConfiguration,

            string state,

            string timeCreated,

            string timeLastModified,

            string unifiedAgentConfigurationId)
        {
            CompartmentId = compartmentId;
            ConfigurationState = configurationState;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            GroupAssociation = groupAssociation;
            Id = id;
            IsEnabled = isEnabled;
            ServiceConfiguration = serviceConfiguration;
            State = state;
            TimeCreated = timeCreated;
            TimeLastModified = timeLastModified;
            UnifiedAgentConfigurationId = unifiedAgentConfigurationId;
        }
    }
}
