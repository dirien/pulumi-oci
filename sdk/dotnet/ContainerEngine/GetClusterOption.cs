// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine
{
    public static class GetClusterOption
    {
        /// <summary>
        /// This data source provides details about a specific Cluster Option resource in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// Get options available for clusters.
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
        ///         var testClusterOption = Output.Create(Oci.ContainerEngine.GetClusterOption.InvokeAsync(new Oci.ContainerEngine.GetClusterOptionArgs
        ///         {
        ///             ClusterOptionId = oci_containerengine_cluster_option.Test_cluster_option.Id,
        ///             CompartmentId = @var.Compartment_id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetClusterOptionResult> InvokeAsync(GetClusterOptionArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetClusterOptionResult>("oci:containerengine/getClusterOption:getClusterOption", args ?? new GetClusterOptionArgs(), options.WithVersion());
    }


    public sealed class GetClusterOptionArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The id of the option set to retrieve. Use "all" get all options, or use a cluster ID to get options specific to the provided cluster.
        /// </summary>
        [Input("clusterOptionId", required: true)]
        public string ClusterOptionId { get; set; } = null!;

        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        public GetClusterOptionArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetClusterOptionResult
    {
        public readonly string ClusterOptionId;
        public readonly string? CompartmentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Available Kubernetes versions.
        /// </summary>
        public readonly ImmutableArray<string> KubernetesVersions;

        [OutputConstructor]
        private GetClusterOptionResult(
            string clusterOptionId,

            string? compartmentId,

            string id,

            ImmutableArray<string> kubernetesVersions)
        {
            ClusterOptionId = clusterOptionId;
            CompartmentId = compartmentId;
            Id = id;
            KubernetesVersions = kubernetesVersions;
        }
    }
}
