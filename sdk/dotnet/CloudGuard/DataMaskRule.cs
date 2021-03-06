// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard
{
    /// <summary>
    /// This resource provides the Data Mask Rule resource in Oracle Cloud Infrastructure Cloud Guard service.
    /// 
    /// Creates a new Data Mask Rule Definition
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
    ///         var testDataMaskRule = new Oci.CloudGuard.DataMaskRule("testDataMaskRule", new Oci.CloudGuard.DataMaskRuleArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             DataMaskCategories = @var.Data_mask_rule_data_mask_categories,
    ///             DisplayName = @var.Data_mask_rule_display_name,
    ///             IamGroupId = oci_identity_group.Test_group.Id,
    ///             TargetSelected = new Oci.CloudGuard.Inputs.DataMaskRuleTargetSelectedArgs
    ///             {
    ///                 Kind = @var.Data_mask_rule_target_selected_kind,
    ///                 Values = @var.Data_mask_rule_target_selected_values,
    ///             },
    ///             DataMaskRuleStatus = @var.Data_mask_rule_data_mask_rule_status,
    ///             DefinedTags = 
    ///             {
    ///                 { "foo-namespace.bar-key", "value" },
    ///             },
    ///             Description = @var.Data_mask_rule_description,
    ///             FreeformTags = 
    ///             {
    ///                 { "bar-key", "value" },
    ///             },
    ///             State = @var.Data_mask_rule_state,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// DataMaskRules can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:cloudguard/dataMaskRule:DataMaskRule test_data_mask_rule "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:cloudguard/dataMaskRule:DataMaskRule")]
    public partial class DataMaskRule : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) Compartment Identifier where the resource is created
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Data Mask Categories
        /// </summary>
        [Output("dataMaskCategories")]
        public Output<ImmutableArray<string>> DataMaskCategories { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The status of the dataMaskRule.
        /// </summary>
        [Output("dataMaskRuleStatus")]
        public Output<string> DataMaskRuleStatus { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// The Data Mask Rule description.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Data Mask Rule name
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) IAM Group id associated with the data mask rule
        /// </summary>
        [Output("iamGroupId")]
        public Output<string> IamGroupId { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecyleDetails")]
        public Output<string> LifecyleDetails { get; private set; } = null!;

        /// <summary>
        /// The current state of the DataMaskRule.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Target Selection eg select ALL or select on basis of TargetResourceTypes or TargetIds.
        /// </summary>
        [Output("targetSelected")]
        public Output<Outputs.DataMaskRuleTargetSelected> TargetSelected { get; private set; } = null!;

        /// <summary>
        /// The date and time the target was created. Format defined by RFC3339.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the target was updated. Format defined by RFC3339.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a DataMaskRule resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DataMaskRule(string name, DataMaskRuleArgs args, CustomResourceOptions? options = null)
            : base("oci:cloudguard/dataMaskRule:DataMaskRule", name, args ?? new DataMaskRuleArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DataMaskRule(string name, Input<string> id, DataMaskRuleState? state = null, CustomResourceOptions? options = null)
            : base("oci:cloudguard/dataMaskRule:DataMaskRule", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DataMaskRule resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DataMaskRule Get(string name, Input<string> id, DataMaskRuleState? state = null, CustomResourceOptions? options = null)
        {
            return new DataMaskRule(name, id, state, options);
        }
    }

    public sealed class DataMaskRuleArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Compartment Identifier where the resource is created
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("dataMaskCategories", required: true)]
        private InputList<string>? _dataMaskCategories;

        /// <summary>
        /// (Updatable) Data Mask Categories
        /// </summary>
        public InputList<string> DataMaskCategories
        {
            get => _dataMaskCategories ?? (_dataMaskCategories = new InputList<string>());
            set => _dataMaskCategories = value;
        }

        /// <summary>
        /// (Updatable) The status of the dataMaskRule.
        /// </summary>
        [Input("dataMaskRuleStatus")]
        public Input<string>? DataMaskRuleStatus { get; set; }

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
        /// The Data Mask Rule description.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Data Mask Rule name
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
        /// (Updatable) IAM Group id associated with the data mask rule
        /// </summary>
        [Input("iamGroupId", required: true)]
        public Input<string> IamGroupId { get; set; } = null!;

        /// <summary>
        /// The current state of the DataMaskRule.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// (Updatable) Target Selection eg select ALL or select on basis of TargetResourceTypes or TargetIds.
        /// </summary>
        [Input("targetSelected", required: true)]
        public Input<Inputs.DataMaskRuleTargetSelectedArgs> TargetSelected { get; set; } = null!;

        public DataMaskRuleArgs()
        {
        }
    }

    public sealed class DataMaskRuleState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Compartment Identifier where the resource is created
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("dataMaskCategories")]
        private InputList<string>? _dataMaskCategories;

        /// <summary>
        /// (Updatable) Data Mask Categories
        /// </summary>
        public InputList<string> DataMaskCategories
        {
            get => _dataMaskCategories ?? (_dataMaskCategories = new InputList<string>());
            set => _dataMaskCategories = value;
        }

        /// <summary>
        /// (Updatable) The status of the dataMaskRule.
        /// </summary>
        [Input("dataMaskRuleStatus")]
        public Input<string>? DataMaskRuleStatus { get; set; }

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
        /// The Data Mask Rule description.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Data Mask Rule name
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

        /// <summary>
        /// (Updatable) IAM Group id associated with the data mask rule
        /// </summary>
        [Input("iamGroupId")]
        public Input<string>? IamGroupId { get; set; }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecyleDetails")]
        public Input<string>? LifecyleDetails { get; set; }

        /// <summary>
        /// The current state of the DataMaskRule.
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
        /// (Updatable) Target Selection eg select ALL or select on basis of TargetResourceTypes or TargetIds.
        /// </summary>
        [Input("targetSelected")]
        public Input<Inputs.DataMaskRuleTargetSelectedGetArgs>? TargetSelected { get; set; }

        /// <summary>
        /// The date and time the target was created. Format defined by RFC3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the target was updated. Format defined by RFC3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public DataMaskRuleState()
        {
        }
    }
}
