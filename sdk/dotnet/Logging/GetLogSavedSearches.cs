// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging
{
    public static class GetLogSavedSearches
    {
        /// <summary>
        /// This data source provides the list of Log Saved Searches in Oracle Cloud Infrastructure Logging service.
        /// 
        /// Lists Logging Saved Searches for this compartment.
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
        ///         var testLogSavedSearches = Output.Create(Oci.Logging.GetLogSavedSearches.InvokeAsync(new Oci.Logging.GetLogSavedSearchesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             LogSavedSearchId = oci_logging_log_saved_search.Test_log_saved_search.Id,
        ///             Name = @var.Log_saved_search_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetLogSavedSearchesResult> InvokeAsync(GetLogSavedSearchesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetLogSavedSearchesResult>("oci:logging/getLogSavedSearches:getLogSavedSearches", args ?? new GetLogSavedSearchesArgs(), options.WithVersion());
    }


    public sealed class GetLogSavedSearchesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetLogSavedSearchesFilterArgs>? _filters;
        public List<Inputs.GetLogSavedSearchesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetLogSavedSearchesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// OCID of the LogSavedSearch
        /// </summary>
        [Input("logSavedSearchId")]
        public string? LogSavedSearchId { get; set; }

        /// <summary>
        /// Resource name
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        public GetLogSavedSearchesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetLogSavedSearchesResult
    {
        /// <summary>
        /// The OCID of the compartment that the resource belongs to.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetLogSavedSearchesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? LogSavedSearchId;
        /// <summary>
        /// The list of log_saved_search_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLogSavedSearchesLogSavedSearchSummaryCollectionResult> LogSavedSearchSummaryCollections;
        /// <summary>
        /// The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? Name;

        [OutputConstructor]
        private GetLogSavedSearchesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetLogSavedSearchesFilterResult> filters,

            string id,

            string? logSavedSearchId,

            ImmutableArray<Outputs.GetLogSavedSearchesLogSavedSearchSummaryCollectionResult> logSavedSearchSummaryCollections,

            string? name)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            LogSavedSearchId = logSavedSearchId;
            LogSavedSearchSummaryCollections = logSavedSearchSummaryCollections;
            Name = name;
        }
    }
}
