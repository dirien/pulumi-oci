// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    /// <summary>
    /// This resource provides the Fleet resource in Oracle Cloud Infrastructure Jms service.
    /// 
    /// Create a new Fleet using the information provided.
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
    ///         var testFleet = new Oci.JmsFleet("testFleet", new Oci.JmsFleetArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             DisplayName = @var.Fleet_display_name,
    ///             DefinedTags = 
    ///             {
    ///                 { "foo-namespace.bar-key", "value" },
    ///             },
    ///             Description = @var.Fleet_description,
    ///             FreeformTags = 
    ///             {
    ///                 { "bar-key", "value" },
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Fleets can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:index/jmsFleet:JmsFleet test_fleet "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:index/jmsFleet:JmsFleet")]
    public partial class JmsFleet : Pulumi.CustomResource
    {
        /// <summary>
        /// The approximate count of all unique applications in the Fleet in the past seven days. This metric is provided on a best-effort manner, and is not taken into account when computing the resource ETag.
        /// </summary>
        [Output("approximateApplicationCount")]
        public Output<int> ApproximateApplicationCount { get; private set; } = null!;

        /// <summary>
        /// The approximate count of all unique Java installations in the Fleet in the past seven days. This metric is provided on a best-effort manner, and is not taken into account when computing the resource ETag.
        /// </summary>
        [Output("approximateInstallationCount")]
        public Output<int> ApproximateInstallationCount { get; private set; } = null!;

        /// <summary>
        /// The approximate count of all unique Java Runtimes in the Fleet in the past seven days. This metric is provided on a best-effort manner, and is not taken into account when computing the resource ETag.
        /// </summary>
        [Output("approximateJreCount")]
        public Output<int> ApproximateJreCount { get; private set; } = null!;

        /// <summary>
        /// The approximate count of all unique managed instances in the Fleet in the past seven days. This metric is provided on a best-effort manner, and is not taken into account when computing the resource ETag.
        /// </summary>
        [Output("approximateManagedInstanceCount")]
        public Output<int> ApproximateManagedInstanceCount { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment of the Fleet.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The Fleet's description. If nothing is provided, the Fleet description will be null.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The name of the Fleet. The displayName must be unique for Fleets in the same compartment.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`. (See [Managing Tags and Tag Namespaces](https://docs.cloud.oracle.com/iaas/Content/Tagging/Concepts/understandingfreeformtags.htm).)
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// The lifecycle state of the Fleet.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The creation date and time of the Fleet (formatted according to RFC3339).
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;


        /// <summary>
        /// Create a JmsFleet resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public JmsFleet(string name, JmsFleetArgs args, CustomResourceOptions? options = null)
            : base("oci:index/jmsFleet:JmsFleet", name, args ?? new JmsFleetArgs(), MakeResourceOptions(options, ""))
        {
        }

        private JmsFleet(string name, Input<string> id, JmsFleetState? state = null, CustomResourceOptions? options = null)
            : base("oci:index/jmsFleet:JmsFleet", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing JmsFleet resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static JmsFleet Get(string name, Input<string> id, JmsFleetState? state = null, CustomResourceOptions? options = null)
        {
            return new JmsFleet(name, id, state, options);
        }
    }

    public sealed class JmsFleetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment of the Fleet.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The Fleet's description. If nothing is provided, the Fleet description will be null.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The name of the Fleet. The displayName must be unique for Fleets in the same compartment.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`. (See [Managing Tags and Tag Namespaces](https://docs.cloud.oracle.com/iaas/Content/Tagging/Concepts/understandingfreeformtags.htm).)
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        public JmsFleetArgs()
        {
        }
    }

    public sealed class JmsFleetState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The approximate count of all unique applications in the Fleet in the past seven days. This metric is provided on a best-effort manner, and is not taken into account when computing the resource ETag.
        /// </summary>
        [Input("approximateApplicationCount")]
        public Input<int>? ApproximateApplicationCount { get; set; }

        /// <summary>
        /// The approximate count of all unique Java installations in the Fleet in the past seven days. This metric is provided on a best-effort manner, and is not taken into account when computing the resource ETag.
        /// </summary>
        [Input("approximateInstallationCount")]
        public Input<int>? ApproximateInstallationCount { get; set; }

        /// <summary>
        /// The approximate count of all unique Java Runtimes in the Fleet in the past seven days. This metric is provided on a best-effort manner, and is not taken into account when computing the resource ETag.
        /// </summary>
        [Input("approximateJreCount")]
        public Input<int>? ApproximateJreCount { get; set; }

        /// <summary>
        /// The approximate count of all unique managed instances in the Fleet in the past seven days. This metric is provided on a best-effort manner, and is not taken into account when computing the resource ETag.
        /// </summary>
        [Input("approximateManagedInstanceCount")]
        public Input<int>? ApproximateManagedInstanceCount { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment of the Fleet.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The Fleet's description. If nothing is provided, the Fleet description will be null.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The name of the Fleet. The displayName must be unique for Fleets in the same compartment.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`. (See [Managing Tags and Tag Namespaces](https://docs.cloud.oracle.com/iaas/Content/Tagging/Concepts/understandingfreeformtags.htm).)
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The lifecycle state of the Fleet.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<object>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<object> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<object>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The creation date and time of the Fleet (formatted according to RFC3339).
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        public JmsFleetState()
        {
        }
    }
}