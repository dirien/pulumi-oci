// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetBlockVolumeReplicas
    {
        /// <summary>
        /// This data source provides the list of Block Volume Replicas in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the block volume replicas in the specified compartment and availability domain.
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
        ///         var testBlockVolumeReplicas = Output.Create(Oci.Core.GetBlockVolumeReplicas.InvokeAsync(new Oci.Core.GetBlockVolumeReplicasArgs
        ///         {
        ///             AvailabilityDomain = @var.Block_volume_replica_availability_domain,
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Block_volume_replica_display_name,
        ///             State = @var.Block_volume_replica_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetBlockVolumeReplicasResult> InvokeAsync(GetBlockVolumeReplicasArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetBlockVolumeReplicasResult>("oci:core/getBlockVolumeReplicas:getBlockVolumeReplicas", args ?? new GetBlockVolumeReplicasArgs(), options.WithVersion());
    }


    public sealed class GetBlockVolumeReplicasArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public string AvailabilityDomain { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetBlockVolumeReplicasFilterArgs>? _filters;
        public List<Inputs.GetBlockVolumeReplicasFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetBlockVolumeReplicasFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetBlockVolumeReplicasArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetBlockVolumeReplicasResult
    {
        /// <summary>
        /// The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The list of block_volume_replicas.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBlockVolumeReplicasBlockVolumeReplicaResult> BlockVolumeReplicas;
        /// <summary>
        /// The OCID of the compartment that contains the block volume replica.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetBlockVolumeReplicasFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of a block volume replica.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetBlockVolumeReplicasResult(
            string availabilityDomain,

            ImmutableArray<Outputs.GetBlockVolumeReplicasBlockVolumeReplicaResult> blockVolumeReplicas,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetBlockVolumeReplicasFilterResult> filters,

            string id,

            string? state)
        {
            AvailabilityDomain = availabilityDomain;
            BlockVolumeReplicas = blockVolumeReplicas;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
