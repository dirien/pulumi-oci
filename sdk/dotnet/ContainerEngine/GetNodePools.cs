// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine
{
    public static class GetNodePools
    {
        /// <summary>
        /// This data source provides the list of Node Pools in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// List all the node pools in a compartment, and optionally filter by cluster.
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
        ///         var testNodePools = Output.Create(Oci.ContainerEngine.GetNodePools.InvokeAsync(new Oci.ContainerEngine.GetNodePoolsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             ClusterId = oci_containerengine_cluster.Test_cluster.Id,
        ///             Name = @var.Node_pool_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetNodePoolsResult> InvokeAsync(GetNodePoolsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetNodePoolsResult>("oci:containerengine/getNodePools:getNodePools", args ?? new GetNodePoolsArgs(), options.WithVersion());
    }


    public sealed class GetNodePoolsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        [Input("clusterId")]
        public string? ClusterId { get; set; }

        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetNodePoolsFilterArgs>? _filters;
        public List<Inputs.GetNodePoolsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNodePoolsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The name to filter on.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        public GetNodePoolsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetNodePoolsResult
    {
        /// <summary>
        /// The OCID of the cluster to which this node pool is attached.
        /// </summary>
        public readonly string? ClusterId;
        /// <summary>
        /// The OCID of the compartment in which the node pool exists.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetNodePoolsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the node.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The list of node_pools.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolsNodePoolResult> NodePools;

        [OutputConstructor]
        private GetNodePoolsResult(
            string? clusterId,

            string compartmentId,

            ImmutableArray<Outputs.GetNodePoolsFilterResult> filters,

            string id,

            string? name,

            ImmutableArray<Outputs.GetNodePoolsNodePoolResult> nodePools)
        {
            ClusterId = clusterId;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            Name = name;
            NodePools = nodePools;
        }
    }
}
