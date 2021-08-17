// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetLogAnalyticsLogAnalyticsLogGroups
    {
        /// <summary>
        /// This data source provides the list of Log Analytics Log Groups in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Returns a list of log groups in a compartment. You may limit the number of log groups, provide sorting options, and filter the results by specifying a display name.
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
        ///         var testLogAnalyticsLogGroups = Output.Create(Oci.GetLogAnalyticsLogAnalyticsLogGroups.InvokeAsync(new Oci.GetLogAnalyticsLogAnalyticsLogGroupsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Namespace = @var.Log_analytics_log_group_namespace,
        ///             DisplayName = @var.Log_analytics_log_group_display_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetLogAnalyticsLogAnalyticsLogGroupsResult> InvokeAsync(GetLogAnalyticsLogAnalyticsLogGroupsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetLogAnalyticsLogAnalyticsLogGroupsResult>("oci:index/getLogAnalyticsLogAnalyticsLogGroups:GetLogAnalyticsLogAnalyticsLogGroups", args ?? new GetLogAnalyticsLogAnalyticsLogGroupsArgs(), options.WithVersion());
    }


    public sealed class GetLogAnalyticsLogAnalyticsLogGroupsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only log analytics log groups whose displayName matches the entire display name given. The match is case-insensitive.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetLogAnalyticsLogAnalyticsLogGroupsFilterArgs>? _filters;
        public List<Inputs.GetLogAnalyticsLogAnalyticsLogGroupsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetLogAnalyticsLogAnalyticsLogGroupsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        public GetLogAnalyticsLogAnalyticsLogGroupsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetLogAnalyticsLogAnalyticsLogGroupsResult
    {
        /// <summary>
        /// Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetLogAnalyticsLogAnalyticsLogGroupsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of log_analytics_log_group_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLogAnalyticsLogAnalyticsLogGroupsLogAnalyticsLogGroupSummaryCollectionResult> LogAnalyticsLogGroupSummaryCollections;
        public readonly string Namespace;

        [OutputConstructor]
        private GetLogAnalyticsLogAnalyticsLogGroupsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetLogAnalyticsLogAnalyticsLogGroupsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetLogAnalyticsLogAnalyticsLogGroupsLogAnalyticsLogGroupSummaryCollectionResult> logAnalyticsLogGroupSummaryCollections,

            string @namespace)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            LogAnalyticsLogGroupSummaryCollections = logAnalyticsLogGroupSummaryCollections;
            Namespace = @namespace;
        }
    }
}