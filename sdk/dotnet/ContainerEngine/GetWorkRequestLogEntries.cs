// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine
{
    public static class GetWorkRequestLogEntries
    {
        /// <summary>
        /// This data source provides the list of Work Request Log Entries in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// Get the logs of a work request.
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
        ///         var testWorkRequestLogEntries = Output.Create(Oci.ContainerEngine.GetWorkRequestLogEntries.InvokeAsync(new Oci.ContainerEngine.GetWorkRequestLogEntriesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             WorkRequestId = oci_containerengine_work_request.Test_work_request.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetWorkRequestLogEntriesResult> InvokeAsync(GetWorkRequestLogEntriesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetWorkRequestLogEntriesResult>("oci:containerengine/getWorkRequestLogEntries:getWorkRequestLogEntries", args ?? new GetWorkRequestLogEntriesArgs(), options.WithVersion());
    }


    public sealed class GetWorkRequestLogEntriesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetWorkRequestLogEntriesFilterArgs>? _filters;
        public List<Inputs.GetWorkRequestLogEntriesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetWorkRequestLogEntriesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the work request.
        /// </summary>
        [Input("workRequestId", required: true)]
        public string WorkRequestId { get; set; } = null!;

        public GetWorkRequestLogEntriesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetWorkRequestLogEntriesResult
    {
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetWorkRequestLogEntriesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string WorkRequestId;
        /// <summary>
        /// The list of work_request_log_entries.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWorkRequestLogEntriesWorkRequestLogEntryResult> WorkRequestLogEntries;

        [OutputConstructor]
        private GetWorkRequestLogEntriesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetWorkRequestLogEntriesFilterResult> filters,

            string id,

            string workRequestId,

            ImmutableArray<Outputs.GetWorkRequestLogEntriesWorkRequestLogEntryResult> workRequestLogEntries)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            WorkRequestId = workRequestId;
            WorkRequestLogEntries = workRequestLogEntries;
        }
    }
}
