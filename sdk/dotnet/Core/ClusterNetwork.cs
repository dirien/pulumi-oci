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
    /// This resource provides the Cluster Network resource in Oracle Cloud Infrastructure Core service.
    /// 
    /// Creates a cluster network. For more information about cluster networks, see
    /// [Managing Cluster Networks](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/managingclusternetworks.htm).
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
    ///         var testClusterNetwork = new Oci.Core.ClusterNetwork("testClusterNetwork", new Oci.Core.ClusterNetworkArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             InstancePools = 
    ///             {
    ///                 new Oci.Core.Inputs.ClusterNetworkInstancePoolArgs
    ///                 {
    ///                     InstanceConfigurationId = oci_core_instance_configuration.Test_instance_configuration.Id,
    ///                     Size = @var.Cluster_network_instance_pools_size,
    ///                     DefinedTags = 
    ///                     {
    ///                         { "Operations.CostCenter", "42" },
    ///                     },
    ///                     DisplayName = @var.Cluster_network_instance_pools_display_name,
    ///                     FreeformTags = 
    ///                     {
    ///                         { "Department", "Finance" },
    ///                     },
    ///                 },
    ///             },
    ///             PlacementConfiguration = new Oci.Core.Inputs.ClusterNetworkPlacementConfigurationArgs
    ///             {
    ///                 AvailabilityDomain = @var.Cluster_network_placement_configuration_availability_domain,
    ///                 PrimarySubnetId = oci_core_subnet.Test_subnet.Id,
    ///                 SecondaryVnicSubnets = 
    ///                 {
    ///                     new Oci.Core.Inputs.ClusterNetworkPlacementConfigurationSecondaryVnicSubnetArgs
    ///                     {
    ///                         SubnetId = oci_core_subnet.Test_subnet.Id,
    ///                         DisplayName = @var.Cluster_network_placement_configuration_secondary_vnic_subnets_display_name,
    ///                     },
    ///                 },
    ///             },
    ///             DefinedTags = 
    ///             {
    ///                 { "Operations.CostCenter", "42" },
    ///             },
    ///             DisplayName = @var.Cluster_network_display_name,
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// ClusterNetworks can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:core/clusterNetwork:ClusterNetwork test_cluster_network "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:core/clusterNetwork:ClusterNetwork")]
    public partial class ClusterNetwork : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The data to create the instance pools in the cluster network.
        /// </summary>
        [Output("instancePools")]
        public Output<ImmutableArray<Outputs.ClusterNetworkInstancePool>> InstancePools { get; private set; } = null!;

        /// <summary>
        /// The location for where the instance pools in a cluster network will place instances.
        /// </summary>
        [Output("placementConfiguration")]
        public Output<Outputs.ClusterNetworkPlacementConfiguration> PlacementConfiguration { get; private set; } = null!;

        /// <summary>
        /// The current state of the cluster network.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the resource was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a ClusterNetwork resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ClusterNetwork(string name, ClusterNetworkArgs args, CustomResourceOptions? options = null)
            : base("oci:core/clusterNetwork:ClusterNetwork", name, args ?? new ClusterNetworkArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ClusterNetwork(string name, Input<string> id, ClusterNetworkState? state = null, CustomResourceOptions? options = null)
            : base("oci:core/clusterNetwork:ClusterNetwork", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ClusterNetwork resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ClusterNetwork Get(string name, Input<string> id, ClusterNetworkState? state = null, CustomResourceOptions? options = null)
        {
            return new ClusterNetwork(name, id, state, options);
        }
    }

    public sealed class ClusterNetworkArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
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
        /// The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

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

        [Input("instancePools", required: true)]
        private InputList<Inputs.ClusterNetworkInstancePoolArgs>? _instancePools;

        /// <summary>
        /// (Updatable) The data to create the instance pools in the cluster network.
        /// </summary>
        public InputList<Inputs.ClusterNetworkInstancePoolArgs> InstancePools
        {
            get => _instancePools ?? (_instancePools = new InputList<Inputs.ClusterNetworkInstancePoolArgs>());
            set => _instancePools = value;
        }

        /// <summary>
        /// The location for where the instance pools in a cluster network will place instances.
        /// </summary>
        [Input("placementConfiguration", required: true)]
        public Input<Inputs.ClusterNetworkPlacementConfigurationArgs> PlacementConfiguration { get; set; } = null!;

        public ClusterNetworkArgs()
        {
        }
    }

    public sealed class ClusterNetworkState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
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
        /// The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

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

        [Input("instancePools")]
        private InputList<Inputs.ClusterNetworkInstancePoolGetArgs>? _instancePools;

        /// <summary>
        /// (Updatable) The data to create the instance pools in the cluster network.
        /// </summary>
        public InputList<Inputs.ClusterNetworkInstancePoolGetArgs> InstancePools
        {
            get => _instancePools ?? (_instancePools = new InputList<Inputs.ClusterNetworkInstancePoolGetArgs>());
            set => _instancePools = value;
        }

        /// <summary>
        /// The location for where the instance pools in a cluster network will place instances.
        /// </summary>
        [Input("placementConfiguration")]
        public Input<Inputs.ClusterNetworkPlacementConfigurationGetArgs>? PlacementConfiguration { get; set; }

        /// <summary>
        /// The current state of the cluster network.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the resource was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public ClusterNetworkState()
        {
        }
    }
}
