// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataFlow
{
    /// <summary>
    /// ## Import
    /// 
    /// PrivateEndpoints can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:dataflow/privateEndpoint:PrivateEndpoint test_private_endpoint "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:dataflow/privateEndpoint:PrivateEndpoint")]
    public partial class PrivateEndpoint : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The OCID of a compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly description. Avoid entering confidential information.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An array of DNS zone names. Example: `[ "app.examplecorp.com", "app.examplecorp2.com" ]`
        /// </summary>
        [Output("dnsZones")]
        public Output<ImmutableArray<string>> DnsZones { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// The detailed messages about the lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
        /// </summary>
        [Output("maxHostCount")]
        public Output<int> MaxHostCount { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An array of network security group OCIDs.
        /// </summary>
        [Output("nsgIds")]
        public Output<ImmutableArray<string>> NsgIds { get; private set; } = null!;

        /// <summary>
        /// The OCID of the user who created the resource.
        /// </summary>
        [Output("ownerPrincipalId")]
        public Output<string> OwnerPrincipalId { get; private set; } = null!;

        /// <summary>
        /// The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
        /// </summary>
        [Output("ownerUserName")]
        public Output<string> OwnerUserName { get; private set; } = null!;

        /// <summary>
        /// The current state of this private endpoint.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The OCID of a subnet.
        /// </summary>
        [Output("subnetId")]
        public Output<string> SubnetId { get; private set; } = null!;

        /// <summary>
        /// The date and time a application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time a application was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a PrivateEndpoint resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PrivateEndpoint(string name, PrivateEndpointArgs args, CustomResourceOptions? options = null)
            : base("oci:dataflow/privateEndpoint:PrivateEndpoint", name, args ?? new PrivateEndpointArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PrivateEndpoint(string name, Input<string> id, PrivateEndpointState? state = null, CustomResourceOptions? options = null)
            : base("oci:dataflow/privateEndpoint:PrivateEndpoint", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing PrivateEndpoint resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PrivateEndpoint Get(string name, Input<string> id, PrivateEndpointState? state = null, CustomResourceOptions? options = null)
        {
            return new PrivateEndpoint(name, id, state, options);
        }
    }

    public sealed class PrivateEndpointArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of a compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly description. Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("dnsZones", required: true)]
        private InputList<string>? _dnsZones;

        /// <summary>
        /// (Updatable) An array of DNS zone names. Example: `[ "app.examplecorp.com", "app.examplecorp2.com" ]`
        /// </summary>
        public InputList<string> DnsZones
        {
            get => _dnsZones ?? (_dnsZones = new InputList<string>());
            set => _dnsZones = value;
        }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
        /// </summary>
        [Input("maxHostCount")]
        public Input<int>? MaxHostCount { get; set; }

        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// (Updatable) An array of network security group OCIDs.
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        /// <summary>
        /// The OCID of a subnet.
        /// </summary>
        [Input("subnetId", required: true)]
        public Input<string> SubnetId { get; set; } = null!;

        public PrivateEndpointArgs()
        {
        }
    }

    public sealed class PrivateEndpointState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of a compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly description. Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("dnsZones")]
        private InputList<string>? _dnsZones;

        /// <summary>
        /// (Updatable) An array of DNS zone names. Example: `[ "app.examplecorp.com", "app.examplecorp2.com" ]`
        /// </summary>
        public InputList<string> DnsZones
        {
            get => _dnsZones ?? (_dnsZones = new InputList<string>());
            set => _dnsZones = value;
        }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The detailed messages about the lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
        /// </summary>
        [Input("maxHostCount")]
        public Input<int>? MaxHostCount { get; set; }

        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// (Updatable) An array of network security group OCIDs.
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        /// <summary>
        /// The OCID of the user who created the resource.
        /// </summary>
        [Input("ownerPrincipalId")]
        public Input<string>? OwnerPrincipalId { get; set; }

        /// <summary>
        /// The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
        /// </summary>
        [Input("ownerUserName")]
        public Input<string>? OwnerUserName { get; set; }

        /// <summary>
        /// The current state of this private endpoint.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The OCID of a subnet.
        /// </summary>
        [Input("subnetId")]
        public Input<string>? SubnetId { get; set; }

        /// <summary>
        /// The date and time a application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time a application was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public PrivateEndpointState()
        {
        }
    }
}