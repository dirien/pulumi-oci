// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics
{
    public static class GetLogAnalyticsEntities
    {
        /// <summary>
        /// This data source provides the list of Log Analytics Entities in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Return a list of log analytics entities.
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
        ///         var testLogAnalyticsEntities = Output.Create(Oci.LogAnalytics.GetLogAnalyticsEntities.InvokeAsync(new Oci.LogAnalytics.GetLogAnalyticsEntitiesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Namespace = @var.Log_analytics_entity_namespace,
        ///             CloudResourceId = oci_log_analytics_cloud_resource.Test_cloud_resource.Id,
        ///             EntityTypeNames = @var.Log_analytics_entity_entity_type_name,
        ///             Hostname = @var.Log_analytics_entity_hostname,
        ///             HostnameContains = @var.Log_analytics_entity_hostname_contains,
        ///             IsManagementAgentIdNull = @var.Log_analytics_entity_is_management_agent_id_null,
        ///             LifecycleDetailsContains = @var.Log_analytics_entity_lifecycle_details_contains,
        ///             Name = @var.Log_analytics_entity_name,
        ///             NameContains = @var.Log_analytics_entity_name_contains,
        ///             SourceId = oci_log_analytics_source.Test_source.Id,
        ///             State = @var.Log_analytics_entity_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetLogAnalyticsEntitiesResult> InvokeAsync(GetLogAnalyticsEntitiesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetLogAnalyticsEntitiesResult>("oci:loganalytics/getLogAnalyticsEntities:getLogAnalyticsEntities", args ?? new GetLogAnalyticsEntitiesArgs(), options.WithVersion());
    }


    public sealed class GetLogAnalyticsEntitiesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only log analytics entities whose cloudResourceId matches the cloudResourceId given.
        /// </summary>
        [Input("cloudResourceId")]
        public string? CloudResourceId { get; set; }

        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("entityTypeNames")]
        private List<string>? _entityTypeNames;

        /// <summary>
        /// A filter to return only log analytics entities whose entityTypeName matches the entire log analytics entity type name of one of the entityTypeNames given in the list. The match is case-insensitive.
        /// </summary>
        public List<string> EntityTypeNames
        {
            get => _entityTypeNames ?? (_entityTypeNames = new List<string>());
            set => _entityTypeNames = value;
        }

        [Input("filters")]
        private List<Inputs.GetLogAnalyticsEntitiesFilterArgs>? _filters;
        public List<Inputs.GetLogAnalyticsEntitiesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetLogAnalyticsEntitiesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only log analytics entities whose hostname matches the entire hostname given.
        /// </summary>
        [Input("hostname")]
        public string? Hostname { get; set; }

        /// <summary>
        /// A filter to return only log analytics entities whose hostname contains the substring given. The match is case-insensitive.
        /// </summary>
        [Input("hostnameContains")]
        public string? HostnameContains { get; set; }

        /// <summary>
        /// A filter to return only those log analytics entities whose managementAgentId is null or is not null.
        /// </summary>
        [Input("isManagementAgentIdNull")]
        public string? IsManagementAgentIdNull { get; set; }

        /// <summary>
        /// A filter to return only log analytics entities whose lifecycleDetails contains the specified string.
        /// </summary>
        [Input("lifecycleDetailsContains")]
        public string? LifecycleDetailsContains { get; set; }

        /// <summary>
        /// A filter to return only log analytics entities whose name matches the entire name given. The match is case-insensitive.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// A filter to return only log analytics entities whose name contains the name given. The match is case-insensitive.
        /// </summary>
        [Input("nameContains")]
        public string? NameContains { get; set; }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        /// <summary>
        /// A filter to return only log analytics entities whose sourceId matches the sourceId given.
        /// </summary>
        [Input("sourceId")]
        public string? SourceId { get; set; }

        /// <summary>
        /// A filter to return only those log analytics entities with the specified lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetLogAnalyticsEntitiesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetLogAnalyticsEntitiesResult
    {
        /// <summary>
        /// The OCID of the Cloud resource which this entity is a representation of. This may be blank when the entity represents a non-cloud resource that the customer may have on their premises.
        /// </summary>
        public readonly string? CloudResourceId;
        /// <summary>
        /// Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Log analytics entity type name.
        /// </summary>
        public readonly ImmutableArray<string> EntityTypeNames;
        public readonly ImmutableArray<Outputs.GetLogAnalyticsEntitiesFilterResult> Filters;
        /// <summary>
        /// The hostname where the entity represented here is actually present. This would be the output one would get if they run `echo $HOSTNAME` on Linux or an equivalent OS command. This may be different from management agents host since logs may be collected remotely.
        /// </summary>
        public readonly string? Hostname;
        public readonly string? HostnameContains;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? IsManagementAgentIdNull;
        public readonly string? LifecycleDetailsContains;
        /// <summary>
        /// The list of log_analytics_entity_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLogAnalyticsEntitiesLogAnalyticsEntityCollectionResult> LogAnalyticsEntityCollections;
        /// <summary>
        /// Log analytics entity name.
        /// </summary>
        public readonly string? Name;
        public readonly string? NameContains;
        public readonly string Namespace;
        /// <summary>
        /// This indicates the type of source. It is primarily for Enterprise Manager Repository ID.
        /// </summary>
        public readonly string? SourceId;
        /// <summary>
        /// The current state of the log analytics entity.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetLogAnalyticsEntitiesResult(
            string? cloudResourceId,

            string compartmentId,

            ImmutableArray<string> entityTypeNames,

            ImmutableArray<Outputs.GetLogAnalyticsEntitiesFilterResult> filters,

            string? hostname,

            string? hostnameContains,

            string id,

            string? isManagementAgentIdNull,

            string? lifecycleDetailsContains,

            ImmutableArray<Outputs.GetLogAnalyticsEntitiesLogAnalyticsEntityCollectionResult> logAnalyticsEntityCollections,

            string? name,

            string? nameContains,

            string @namespace,

            string? sourceId,

            string? state)
        {
            CloudResourceId = cloudResourceId;
            CompartmentId = compartmentId;
            EntityTypeNames = entityTypeNames;
            Filters = filters;
            Hostname = hostname;
            HostnameContains = hostnameContains;
            Id = id;
            IsManagementAgentIdNull = isManagementAgentIdNull;
            LifecycleDetailsContains = lifecycleDetailsContains;
            LogAnalyticsEntityCollections = logAnalyticsEntityCollections;
            Name = name;
            NameContains = nameContains;
            Namespace = @namespace;
            SourceId = sourceId;
            State = state;
        }
    }
}
