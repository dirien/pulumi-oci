// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetDbNodes
    {
        /// <summary>
        /// This data source provides the list of Db Nodes in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the database nodes in the specified DB system and compartment. A database node is a server running database software.
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
        ///         var testDbNodes = Output.Create(Oci.Database.GetDbNodes.InvokeAsync(new Oci.Database.GetDbNodesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DbSystemId = oci_database_db_system.Test_db_system.Id,
        ///             State = @var.Db_node_state,
        ///             VmClusterId = oci_database_vm_cluster.Test_vm_cluster.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDbNodesResult> InvokeAsync(GetDbNodesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDbNodesResult>("oci:database/getDbNodes:getDbNodes", args ?? new GetDbNodesArgs(), options.WithVersion());
    }


    public sealed class GetDbNodesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). If provided, filters the results to the set of database versions which are supported for the DB system.
        /// </summary>
        [Input("dbSystemId")]
        public string? DbSystemId { get; set; }

        [Input("filters")]
        private List<Inputs.GetDbNodesFilterArgs>? _filters;
        public List<Inputs.GetDbNodesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDbNodesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
        /// </summary>
        [Input("vmClusterId")]
        public string? VmClusterId { get; set; }

        public GetDbNodesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDbNodesResult
    {
        public readonly string CompartmentId;
        /// <summary>
        /// The list of db_nodes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbNodesDbNodeResult> DbNodes;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
        /// </summary>
        public readonly string? DbSystemId;
        public readonly ImmutableArray<Outputs.GetDbNodesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of the database node.
        /// </summary>
        public readonly string? State;
        public readonly string? VmClusterId;

        [OutputConstructor]
        private GetDbNodesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetDbNodesDbNodeResult> dbNodes,

            string? dbSystemId,

            ImmutableArray<Outputs.GetDbNodesFilterResult> filters,

            string id,

            string? state,

            string? vmClusterId)
        {
            CompartmentId = compartmentId;
            DbNodes = dbNodes;
            DbSystemId = dbSystemId;
            Filters = filters;
            Id = id;
            State = state;
            VmClusterId = vmClusterId;
        }
    }
}
