// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement
{
    /// <summary>
    /// This resource provides the Managed Instance Group resource in Oracle Cloud Infrastructure OS Management service.
    /// 
    /// Creates a new Managed Instance Group on the management system.
    /// This will not contain any managed instances after it is first created,
    /// and they must be added later.
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
    ///         var testManagedInstanceGroup = new Oci.OsManagement.ManagedInstanceGroup("testManagedInstanceGroup", new Oci.OsManagement.ManagedInstanceGroupArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             DisplayName = @var.Managed_instance_group_display_name,
    ///             DefinedTags = 
    ///             {
    ///                 { "foo-namespace.bar-key", "value" },
    ///             },
    ///             Description = @var.Managed_instance_group_description,
    ///             FreeformTags = 
    ///             {
    ///                 { "bar-key", "value" },
    ///             },
    ///             OsFamily = @var.Managed_instance_group_os_family,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// ManagedInstanceGroups can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:osmanagement/managedInstanceGroup:ManagedInstanceGroup test_managed_instance_group "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:osmanagement/managedInstanceGroup:ManagedInstanceGroup")]
    public partial class ManagedInstanceGroup : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) OCID for the Compartment
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Information specified by the user about the managed instance group
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Managed Instance Group identifier
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        [Output("managedInstanceCount")]
        public Output<int> ManagedInstanceCount { get; private set; } = null!;

        /// <summary>
        /// list of Managed Instances in the group
        /// </summary>
        [Output("managedInstances")]
        public Output<ImmutableArray<Outputs.ManagedInstanceGroupManagedInstance>> ManagedInstances { get; private set; } = null!;

        /// <summary>
        /// The Operating System type of the managed instance(s) on which this scheduled job will operate. If not specified, this defaults to Linux.
        /// </summary>
        [Output("osFamily")]
        public Output<string> OsFamily { get; private set; } = null!;

        /// <summary>
        /// The current state of the Software Source.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;


        /// <summary>
        /// Create a ManagedInstanceGroup resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ManagedInstanceGroup(string name, ManagedInstanceGroupArgs args, CustomResourceOptions? options = null)
            : base("oci:osmanagement/managedInstanceGroup:ManagedInstanceGroup", name, args ?? new ManagedInstanceGroupArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ManagedInstanceGroup(string name, Input<string> id, ManagedInstanceGroupState? state = null, CustomResourceOptions? options = null)
            : base("oci:osmanagement/managedInstanceGroup:ManagedInstanceGroup", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ManagedInstanceGroup resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ManagedInstanceGroup Get(string name, Input<string> id, ManagedInstanceGroupState? state = null, CustomResourceOptions? options = null)
        {
            return new ManagedInstanceGroup(name, id, state, options);
        }
    }

    public sealed class ManagedInstanceGroupArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) OCID for the Compartment
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Information specified by the user about the managed instance group
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Managed Instance Group identifier
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The Operating System type of the managed instance(s) on which this scheduled job will operate. If not specified, this defaults to Linux.
        /// </summary>
        [Input("osFamily")]
        public Input<string>? OsFamily { get; set; }

        public ManagedInstanceGroupArgs()
        {
        }
    }

    public sealed class ManagedInstanceGroupState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) OCID for the Compartment
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Information specified by the user about the managed instance group
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Managed Instance Group identifier
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("managedInstanceCount")]
        public Input<int>? ManagedInstanceCount { get; set; }

        [Input("managedInstances")]
        private InputList<Inputs.ManagedInstanceGroupManagedInstanceGetArgs>? _managedInstances;

        /// <summary>
        /// list of Managed Instances in the group
        /// </summary>
        public InputList<Inputs.ManagedInstanceGroupManagedInstanceGetArgs> ManagedInstances
        {
            get => _managedInstances ?? (_managedInstances = new InputList<Inputs.ManagedInstanceGroupManagedInstanceGetArgs>());
            set => _managedInstances = value;
        }

        /// <summary>
        /// The Operating System type of the managed instance(s) on which this scheduled job will operate. If not specified, this defaults to Linux.
        /// </summary>
        [Input("osFamily")]
        public Input<string>? OsFamily { get; set; }

        /// <summary>
        /// The current state of the Software Source.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public ManagedInstanceGroupState()
        {
        }
    }
}
