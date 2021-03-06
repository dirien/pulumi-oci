// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Audit
{
    public static class GetEvents
    {
        /// <summary>
        /// This data source provides the list of Audit Events in Oracle Cloud Infrastructure Audit service.
        /// 
        /// Returns all the audit events processed for the specified compartment within the specified
        /// time range.
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
        ///         var testAuditEvents = Output.Create(Oci.Audit.GetEvents.InvokeAsync(new Oci.Audit.GetEventsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             EndTime = @var.Audit_event_end_time,
        ///             StartTime = @var.Audit_event_start_time,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetEventsResult> InvokeAsync(GetEventsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetEventsResult>("oci:audit/getEvents:getEvents", args ?? new GetEventsArgs(), options.WithVersion());
    }


    public sealed class GetEventsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Returns events that were processed before this end date and time, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
        /// </summary>
        [Input("endTime", required: true)]
        public string EndTime { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetEventsFilterArgs>? _filters;
        public List<Inputs.GetEventsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetEventsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Returns events that were processed at or after this start date and time, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
        /// </summary>
        [Input("startTime", required: true)]
        public string StartTime { get; set; } = null!;

        public GetEventsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetEventsResult
    {
        /// <summary>
        /// The list of audit_events.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetEventsAuditEventResult> AuditEvents;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment of the resource  emitting the event.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string EndTime;
        public readonly ImmutableArray<Outputs.GetEventsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string StartTime;

        [OutputConstructor]
        private GetEventsResult(
            ImmutableArray<Outputs.GetEventsAuditEventResult> auditEvents,

            string compartmentId,

            string endTime,

            ImmutableArray<Outputs.GetEventsFilterResult> filters,

            string id,

            string startTime)
        {
            AuditEvents = auditEvents;
            CompartmentId = compartmentId;
            EndTime = endTime;
            Filters = filters;
            Id = id;
            StartTime = startTime;
        }
    }
}
