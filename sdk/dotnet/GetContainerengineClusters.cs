// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetContainerengineClusters
    {
        /// <summary>
        /// This data source provides the list of Clusters in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// List all the cluster objects in a compartment.
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
        ///         var testClusters = Output.Create(Oci.GetContainerengineClusters.InvokeAsync(new Oci.GetContainerengineClustersArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Name = @var.Cluster_name,
        ///             States = @var.Cluster_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetContainerengineClustersResult> InvokeAsync(GetContainerengineClustersArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetContainerengineClustersResult>("oci:index/getContainerengineClusters:GetContainerengineClusters", args ?? new GetContainerengineClustersArgs(), options.WithVersion());
    }


    public sealed class GetContainerengineClustersArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetContainerengineClustersFilterArgs>? _filters;
        public List<Inputs.GetContainerengineClustersFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetContainerengineClustersFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The name to filter on.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        [Input("states")]
        private List<string>? _states;

        /// <summary>
        /// A cluster lifecycle state to filter on. Can have multiple parameters of this name.
        /// </summary>
        public List<string> States
        {
            get => _states ?? (_states = new List<string>());
            set => _states = value;
        }

        public GetContainerengineClustersArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetContainerengineClustersResult
    {
        /// <summary>
        /// The list of clusters.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetContainerengineClustersClusterResult> Clusters;
        /// <summary>
        /// The OCID of the compartment in which the cluster exists.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetContainerengineClustersFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the cluster.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The state of the cluster masters.
        /// </summary>
        public readonly ImmutableArray<string> States;

        [OutputConstructor]
        private GetContainerengineClustersResult(
            ImmutableArray<Outputs.GetContainerengineClustersClusterResult> clusters,

            string compartmentId,

            ImmutableArray<Outputs.GetContainerengineClustersFilterResult> filters,

            string id,

            string? name,

            ImmutableArray<string> states)
        {
            Clusters = clusters;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            Name = name;
            States = states;
        }
    }
}