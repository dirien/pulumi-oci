// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Blockchain
{
    public static class GetPeers
    {
        /// <summary>
        /// This data source provides the list of Peers in Oracle Cloud Infrastructure Blockchain service.
        /// 
        /// List Blockchain Platform Peers
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
        ///         var testPeers = Output.Create(Oci.Blockchain.GetPeers.InvokeAsync(new Oci.Blockchain.GetPeersArgs
        ///         {
        ///             BlockchainPlatformId = oci_blockchain_blockchain_platform.Test_blockchain_platform.Id,
        ///             DisplayName = @var.Peer_display_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetPeersResult> InvokeAsync(GetPeersArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPeersResult>("oci:blockchain/getPeers:getPeers", args ?? new GetPeersArgs(), options.WithVersion());
    }


    public sealed class GetPeersArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique service identifier.
        /// </summary>
        [Input("blockchainPlatformId", required: true)]
        public string BlockchainPlatformId { get; set; } = null!;

        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Example: `My new resource`
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetPeersFilterArgs>? _filters;
        public List<Inputs.GetPeersFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetPeersFilterArgs>());
            set => _filters = value;
        }

        public GetPeersArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetPeersResult
    {
        public readonly string BlockchainPlatformId;
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetPeersFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of peer_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPeersPeerCollectionResult> PeerCollections;

        [OutputConstructor]
        private GetPeersResult(
            string blockchainPlatformId,

            string? displayName,

            ImmutableArray<Outputs.GetPeersFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetPeersPeerCollectionResult> peerCollections)
        {
            BlockchainPlatformId = blockchainPlatformId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            PeerCollections = peerCollections;
        }
    }
}
