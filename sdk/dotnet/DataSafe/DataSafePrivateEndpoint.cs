// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    /// <summary>
    /// This resource provides the Data Safe Private Endpoint resource in Oracle Cloud Infrastructure Data Safe service.
    /// 
    /// Creates a new Data Safe private endpoint.
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
    ///         var testDataSafePrivateEndpoint = new Oci.DataSafe.DataSafePrivateEndpoint("testDataSafePrivateEndpoint", new Oci.DataSafe.DataSafePrivateEndpointArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             DisplayName = @var.Data_safe_private_endpoint_display_name,
    ///             SubnetId = oci_core_subnet.Test_subnet.Id,
    ///             VcnId = oci_core_vcn.Test_vcn.Id,
    ///             DefinedTags = 
    ///             {
    ///                 { "Operations.CostCenter", "42" },
    ///             },
    ///             Description = @var.Data_safe_private_endpoint_description,
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///             NsgIds = @var.Data_safe_private_endpoint_nsg_ids,
    ///             PrivateEndpointIp = @var.Data_safe_private_endpoint_private_endpoint_ip,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// DataSafePrivateEndpoints can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:datasafe/dataSafePrivateEndpoint:DataSafePrivateEndpoint test_data_safe_private_endpoint "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:datasafe/dataSafePrivateEndpoint:DataSafePrivateEndpoint")]
    public partial class DataSafePrivateEndpoint : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The description of the private endpoint.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The display name for the private endpoint. The name does not have to be unique, and it's changeable.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The three-label fully qualified domain name (FQDN) of the private endpoint. The customer VCN's DNS records are updated with this FQDN.
        /// </summary>
        [Output("endpointFqdn")]
        public Output<string> EndpointFqdn { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCIDs of the network security groups that the private endpoint belongs to.
        /// </summary>
        [Output("nsgIds")]
        public Output<ImmutableArray<string>> NsgIds { get; private set; } = null!;

        /// <summary>
        /// The OCID of the underlying private endpoint.
        /// </summary>
        [Output("privateEndpointId")]
        public Output<string> PrivateEndpointId { get; private set; } = null!;

        /// <summary>
        /// The private IP address of the private endpoint.
        /// </summary>
        [Output("privateEndpointIp")]
        public Output<string> PrivateEndpointIp { get; private set; } = null!;

        /// <summary>
        /// The current state of the private endpoint.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The OCID of the subnet.
        /// </summary>
        [Output("subnetId")]
        public Output<string> SubnetId { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time the private endpoint was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The OCID of the VCN.
        /// </summary>
        [Output("vcnId")]
        public Output<string> VcnId { get; private set; } = null!;


        /// <summary>
        /// Create a DataSafePrivateEndpoint resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DataSafePrivateEndpoint(string name, DataSafePrivateEndpointArgs args, CustomResourceOptions? options = null)
            : base("oci:datasafe/dataSafePrivateEndpoint:DataSafePrivateEndpoint", name, args ?? new DataSafePrivateEndpointArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DataSafePrivateEndpoint(string name, Input<string> id, DataSafePrivateEndpointState? state = null, CustomResourceOptions? options = null)
            : base("oci:datasafe/dataSafePrivateEndpoint:DataSafePrivateEndpoint", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DataSafePrivateEndpoint resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DataSafePrivateEndpoint Get(string name, Input<string> id, DataSafePrivateEndpointState? state = null, CustomResourceOptions? options = null)
        {
            return new DataSafePrivateEndpoint(name, id, state, options);
        }
    }

    public sealed class DataSafePrivateEndpointArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description of the private endpoint.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The display name for the private endpoint. The name does not have to be unique, and it's changeable.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// (Updatable) The OCIDs of the network security groups that the private endpoint belongs to.
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        /// <summary>
        /// The private IP address of the private endpoint.
        /// </summary>
        [Input("privateEndpointIp")]
        public Input<string>? PrivateEndpointIp { get; set; }

        /// <summary>
        /// The OCID of the subnet.
        /// </summary>
        [Input("subnetId", required: true)]
        public Input<string> SubnetId { get; set; } = null!;

        /// <summary>
        /// The OCID of the VCN.
        /// </summary>
        [Input("vcnId", required: true)]
        public Input<string> VcnId { get; set; } = null!;

        public DataSafePrivateEndpointArgs()
        {
        }
    }

    public sealed class DataSafePrivateEndpointState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description of the private endpoint.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The display name for the private endpoint. The name does not have to be unique, and it's changeable.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The three-label fully qualified domain name (FQDN) of the private endpoint. The customer VCN's DNS records are updated with this FQDN.
        /// </summary>
        [Input("endpointFqdn")]
        public Input<string>? EndpointFqdn { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// (Updatable) The OCIDs of the network security groups that the private endpoint belongs to.
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        /// <summary>
        /// The OCID of the underlying private endpoint.
        /// </summary>
        [Input("privateEndpointId")]
        public Input<string>? PrivateEndpointId { get; set; }

        /// <summary>
        /// The private IP address of the private endpoint.
        /// </summary>
        [Input("privateEndpointIp")]
        public Input<string>? PrivateEndpointIp { get; set; }

        /// <summary>
        /// The current state of the private endpoint.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The OCID of the subnet.
        /// </summary>
        [Input("subnetId")]
        public Input<string>? SubnetId { get; set; }

        [Input("systemTags")]
        private InputMap<object>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<object> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<object>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The date and time the private endpoint was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The OCID of the VCN.
        /// </summary>
        [Input("vcnId")]
        public Input<string>? VcnId { get; set; }

        public DataSafePrivateEndpointState()
        {
        }
    }
}
