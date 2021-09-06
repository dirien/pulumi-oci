// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics
{
    public static class GetLogAnalyticsLogGroupsSummary
    {
        /// <summary>
        /// This data source provides details about a specific Log Analytics Log Groups Summary resource in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Returns the count of log groups in a compartment.
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
        ///         var testLogAnalyticsLogGroupsSummary = Output.Create(Oci.LogAnalytics.GetLogAnalyticsLogGroupsSummary.InvokeAsync(new Oci.LogAnalytics.GetLogAnalyticsLogGroupsSummaryArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Namespace = @var.Log_analytics_log_groups_summary_namespace,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetLogAnalyticsLogGroupsSummaryResult> InvokeAsync(GetLogAnalyticsLogGroupsSummaryArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetLogAnalyticsLogGroupsSummaryResult>("oci:loganalytics/getLogAnalyticsLogGroupsSummary:getLogAnalyticsLogGroupsSummary", args ?? new GetLogAnalyticsLogGroupsSummaryArgs(), options.WithVersion());
    }


    public sealed class GetLogAnalyticsLogGroupsSummaryArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        public GetLogAnalyticsLogGroupsSummaryArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetLogAnalyticsLogGroupsSummaryResult
    {
        public readonly string CompartmentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly int LogGroupCount;
        public readonly string Namespace;

        [OutputConstructor]
        private GetLogAnalyticsLogGroupsSummaryResult(
            string compartmentId,

            string id,

            int logGroupCount,

            string @namespace)
        {
            CompartmentId = compartmentId;
            Id = id;
            LogGroupCount = logGroupCount;
            Namespace = @namespace;
        }
    }
}
