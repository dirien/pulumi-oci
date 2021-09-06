// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging
{
    public static class GetLogSavedSearch
    {
        /// <summary>
        /// This data source provides details about a specific Log Saved Search resource in Oracle Cloud Infrastructure Logging service.
        /// 
        /// Retrieves a log saved search.
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
        ///         var testLogSavedSearch = Output.Create(Oci.Logging.GetLogSavedSearch.InvokeAsync(new Oci.Logging.GetLogSavedSearchArgs
        ///         {
        ///             LogSavedSearchId = oci_logging_log_saved_search.Test_log_saved_search.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetLogSavedSearchResult> InvokeAsync(GetLogSavedSearchArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetLogSavedSearchResult>("oci:logging/getLogSavedSearch:getLogSavedSearch", args ?? new GetLogSavedSearchArgs(), options.WithVersion());
    }


    public sealed class GetLogSavedSearchArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// OCID of the logSavedSearch
        /// </summary>
        [Input("logSavedSearchId", required: true)]
        public string LogSavedSearchId { get; set; } = null!;

        public GetLogSavedSearchArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetLogSavedSearchResult
    {
        /// <summary>
        /// The OCID of the compartment that the resource belongs to.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Description for this resource.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID of the resource.
        /// </summary>
        public readonly string Id;
        public readonly string LogSavedSearchId;
        /// <summary>
        /// The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The search query that is saved.
        /// </summary>
        public readonly string Query;
        /// <summary>
        /// The state of the LogSavedSearch
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

        [OutputConstructor]
        private GetLogSavedSearchResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string logSavedSearchId,

            string name,

            string query,

            string state,

            string timeCreated,

            string timeLastModified)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            FreeformTags = freeformTags;
            Id = id;
            LogSavedSearchId = logSavedSearchId;
            Name = name;
            Query = query;
            State = state;
            TimeCreated = timeCreated;
            TimeLastModified = timeLastModified;
        }
    }
}
