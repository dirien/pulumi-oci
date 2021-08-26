// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetVmClusterUpdateHistoryEntries
    {
        /// <summary>
        /// This data source provides the list of Vm Cluster Update History Entries in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets the history of the maintenance update actions performed on the specified VM cluster. Applies to Exadata Cloud@Customer instances only.
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
        ///         var testVmClusterUpdateHistoryEntries = Output.Create(Oci.Database.GetVmClusterUpdateHistoryEntries.InvokeAsync(new Oci.Database.GetVmClusterUpdateHistoryEntriesArgs
        ///         {
        ///             VmClusterId = oci_database_vm_cluster.Test_vm_cluster.Id,
        ///             State = @var.Vm_cluster_update_history_entry_state,
        ///             UpdateType = @var.Vm_cluster_update_history_entry_update_type,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetVmClusterUpdateHistoryEntriesResult> InvokeAsync(GetVmClusterUpdateHistoryEntriesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVmClusterUpdateHistoryEntriesResult>("oci:database/getVmClusterUpdateHistoryEntries:getVmClusterUpdateHistoryEntries", args ?? new GetVmClusterUpdateHistoryEntriesArgs(), options.WithVersion());
    }


    public sealed class GetVmClusterUpdateHistoryEntriesArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetVmClusterUpdateHistoryEntriesFilterArgs>? _filters;
        public List<Inputs.GetVmClusterUpdateHistoryEntriesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetVmClusterUpdateHistoryEntriesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given update type exactly.
        /// </summary>
        [Input("updateType")]
        public string? UpdateType { get; set; }

        /// <summary>
        /// The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("vmClusterId", required: true)]
        public string VmClusterId { get; set; } = null!;

        public GetVmClusterUpdateHistoryEntriesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetVmClusterUpdateHistoryEntriesResult
    {
        public readonly ImmutableArray<Outputs.GetVmClusterUpdateHistoryEntriesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current lifecycle state of the maintenance update operation.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The type of VM cluster maintenance update.
        /// </summary>
        public readonly string? UpdateType;
        public readonly string VmClusterId;
        /// <summary>
        /// The list of vm_cluster_update_history_entries.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVmClusterUpdateHistoryEntriesVmClusterUpdateHistoryEntryResult> VmClusterUpdateHistoryEntries;

        [OutputConstructor]
        private GetVmClusterUpdateHistoryEntriesResult(
            ImmutableArray<Outputs.GetVmClusterUpdateHistoryEntriesFilterResult> filters,

            string id,

            string? state,

            string? updateType,

            string vmClusterId,

            ImmutableArray<Outputs.GetVmClusterUpdateHistoryEntriesVmClusterUpdateHistoryEntryResult> vmClusterUpdateHistoryEntries)
        {
            Filters = filters;
            Id = id;
            State = state;
            UpdateType = updateType;
            VmClusterId = vmClusterId;
            VmClusterUpdateHistoryEntries = vmClusterUpdateHistoryEntries;
        }
    }
}
