// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    /// <summary>
    /// This resource provides the Remote Peering Connection resource in Oracle Cloud Infrastructure Core service.
    /// 
    /// Creates a new remote peering connection (RPC) for the specified DRG.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testRemotePeeringConnection = new Oci.Core.RemotePeeringConnection("testRemotePeeringConnection", new Oci.Core.RemotePeeringConnectionArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             DrgId = oci_core_drg.Test_drg.Id,
    ///             DefinedTags = 
    ///             {
    ///                 { "Operations.CostCenter", "42" },
    ///             },
    ///             DisplayName = @var.Remote_peering_connection_display_name,
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///             PeerId = oci_core_remote_peering_connection.Test_remote_peering_connection2.Id,
    ///             PeerRegionName = @var.Remote_peering_connection_peer_region_name,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// RemotePeeringConnections can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:core/remotePeeringConnection:RemotePeeringConnection test_remote_peering_connection "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:core/remotePeeringConnection:RemotePeeringConnection")]
    public partial class RemotePeeringConnection : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment to contain the RPC.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The OCID of the DRG the RPC belongs to.
        /// </summary>
        [Output("drgId")]
        public Output<string> DrgId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
        /// </summary>
        [Output("isCrossTenancyPeering")]
        public Output<bool> IsCrossTenancyPeering { get; private set; } = null!;

        /// <summary>
        /// The OCID of the RPC you want to peer with.
        /// </summary>
        [Output("peerId")]
        public Output<string> PeerId { get; private set; } = null!;

        /// <summary>
        /// The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
        /// </summary>
        [Output("peerRegionName")]
        public Output<string> PeerRegionName { get; private set; } = null!;

        /// <summary>
        /// If this RPC is peered, this value is the OCID of the other RPC's tenancy.
        /// </summary>
        [Output("peerTenancyId")]
        public Output<string> PeerTenancyId { get; private set; } = null!;

        /// <summary>
        /// Whether the RPC is peered with another RPC. `NEW` means the RPC has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the RPC at the other end of the peering has been deleted.
        /// </summary>
        [Output("peeringStatus")]
        public Output<string> PeeringStatus { get; private set; } = null!;

        /// <summary>
        /// The RPC's current lifecycle state.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the RPC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;


        /// <summary>
        /// Create a RemotePeeringConnection resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public RemotePeeringConnection(string name, RemotePeeringConnectionArgs args, CustomResourceOptions? options = null)
            : base("oci:core/remotePeeringConnection:RemotePeeringConnection", name, args ?? new RemotePeeringConnectionArgs(), MakeResourceOptions(options, ""))
        {
        }

        private RemotePeeringConnection(string name, Input<string> id, RemotePeeringConnectionState? state = null, CustomResourceOptions? options = null)
            : base("oci:core/remotePeeringConnection:RemotePeeringConnection", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing RemotePeeringConnection resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static RemotePeeringConnection Get(string name, Input<string> id, RemotePeeringConnectionState? state = null, CustomResourceOptions? options = null)
        {
            return new RemotePeeringConnection(name, id, state, options);
        }
    }

    public sealed class RemotePeeringConnectionArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment to contain the RPC.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The OCID of the DRG the RPC belongs to.
        /// </summary>
        [Input("drgId", required: true)]
        public Input<string> DrgId { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The OCID of the RPC you want to peer with.
        /// </summary>
        [Input("peerId")]
        public Input<string>? PeerId { get; set; }

        /// <summary>
        /// The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
        /// </summary>
        [Input("peerRegionName")]
        public Input<string>? PeerRegionName { get; set; }

        public RemotePeeringConnectionArgs()
        {
        }
    }

    public sealed class RemotePeeringConnectionState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment to contain the RPC.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The OCID of the DRG the RPC belongs to.
        /// </summary>
        [Input("drgId")]
        public Input<string>? DrgId { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
        /// </summary>
        [Input("isCrossTenancyPeering")]
        public Input<bool>? IsCrossTenancyPeering { get; set; }

        /// <summary>
        /// The OCID of the RPC you want to peer with.
        /// </summary>
        [Input("peerId")]
        public Input<string>? PeerId { get; set; }

        /// <summary>
        /// The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
        /// </summary>
        [Input("peerRegionName")]
        public Input<string>? PeerRegionName { get; set; }

        /// <summary>
        /// If this RPC is peered, this value is the OCID of the other RPC's tenancy.
        /// </summary>
        [Input("peerTenancyId")]
        public Input<string>? PeerTenancyId { get; set; }

        /// <summary>
        /// Whether the RPC is peered with another RPC. `NEW` means the RPC has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the RPC at the other end of the peering has been deleted.
        /// </summary>
        [Input("peeringStatus")]
        public Input<string>? PeeringStatus { get; set; }

        /// <summary>
        /// The RPC's current lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the RPC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        public RemotePeeringConnectionState()
        {
        }
    }
}
