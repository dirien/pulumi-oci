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
    /// This resource provides the Target resource in Oracle Cloud Infrastructure Cloud Guard service.
    /// 
    /// Creates a new Target
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
    ///         var testTarget = new Oci.CloudGuard.Target("testTarget", new Oci.CloudGuard.TargetArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             DisplayName = @var.Target_display_name,
    ///             TargetResourceId = oci_cloud_guard_target_resource.Test_target_resource.Id,
    ///             TargetResourceType = @var.Target_target_resource_type,
    ///             DefinedTags = 
    ///             {
    ///                 { "foo-namespace.bar-key", "value" },
    ///             },
    ///             Description = @var.Target_description,
    ///             FreeformTags = 
    ///             {
    ///                 { "bar-key", "value" },
    ///             },
    ///             State = @var.Target_state,
    ///             TargetDetectorRecipes = 
    ///             {
    ///                 new Oci.CloudGuard.Inputs.TargetTargetDetectorRecipeArgs
    ///                 {
    ///                     DetectorRecipeId = oci_cloud_guard_detector_recipe.Test_detector_recipe.Id,
    ///                     DetectorRules = 
    ///                     {
    ///                         new Oci.CloudGuard.Inputs.TargetTargetDetectorRecipeDetectorRuleArgs
    ///                         {
    ///                             Details = new Oci.CloudGuard.Inputs.TargetTargetDetectorRecipeDetectorRuleDetailsArgs
    ///                             {
    ///                                 ConditionGroups = 
    ///                                 {
    ///                                     new Oci.CloudGuard.Inputs.TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs
    ///                                     {
    ///                                         CompartmentId = @var.Compartment_id,
    ///                                         Condition = @var.Target_target_detector_recipes_detector_rules_details_condition_groups_condition,
    ///                                     },
    ///                                 },
    ///                             },
    ///                             DetectorRuleId = oci_events_rule.Test_rule.Id,
    ///                         },
    ///                     },
    ///                 },
    ///             },
    ///             TargetResponderRecipes = 
    ///             {
    ///                 new Oci.CloudGuard.Inputs.TargetTargetResponderRecipeArgs
    ///                 {
    ///                     ResponderRecipeId = oci_cloud_guard_responder_recipe.Test_responder_recipe.Id,
    ///                     ResponderRules = 
    ///                     {
    ///                         new Oci.CloudGuard.Inputs.TargetTargetResponderRecipeResponderRuleArgs
    ///                         {
    ///                             Details = new Oci.CloudGuard.Inputs.TargetTargetResponderRecipeResponderRuleDetailsArgs
    ///                             {
    ///                                 Condition = @var.Target_target_responder_recipes_responder_rules_details_condition,
    ///                                 Configurations = 
    ///                                 {
    ///                                     new Oci.CloudGuard.Inputs.TargetTargetResponderRecipeResponderRuleDetailsConfigurationArgs
    ///                                     {
    ///                                         ConfigKey = @var.Target_target_responder_recipes_responder_rules_details_configurations_config_key,
    ///                                         Name = @var.Target_target_responder_recipes_responder_rules_details_configurations_name,
    ///                                         Value = @var.Target_target_responder_recipes_responder_rules_details_configurations_value,
    ///                                     },
    ///                                 },
    ///                                 Mode = @var.Target_target_responder_recipes_responder_rules_details_mode,
    ///                             },
    ///                             ResponderRuleId = oci_events_rule.Test_rule.Id,
    ///                         },
    ///                     },
    ///                 },
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Targets can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:cloudguard/target:Target test_target "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:cloudguard/target:Target")]
    public partial class Target : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) compartment associated with condition
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// The target description.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) DetectorTemplate Identifier
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// List of inherited compartments
        /// </summary>
        [Output("inheritedByCompartments")]
        public Output<ImmutableArray<string>> InheritedByCompartments { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecyleDetails")]
        public Output<string> LifecyleDetails { get; private set; } = null!;

        /// <summary>
        /// Total number of recipes attached to target
        /// </summary>
        [Output("recipeCount")]
        public Output<int> RecipeCount { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The current state of the DetectorRule.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) List of detector recipes to associate with target
        /// </summary>
        [Output("targetDetectorRecipes")]
        public Output<ImmutableArray<Outputs.TargetTargetDetectorRecipe>> TargetDetectorRecipes { get; private set; } = null!;

        /// <summary>
        /// Resource ID which the target uses to monitor
        /// </summary>
        [Output("targetResourceId")]
        public Output<string> TargetResourceId { get; private set; } = null!;

        /// <summary>
        /// possible type of targets(compartment/HCMCloud/ERPCloud)
        /// </summary>
        [Output("targetResourceType")]
        public Output<string> TargetResourceType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) List of responder recipes to associate with target
        /// </summary>
        [Output("targetResponderRecipes")]
        public Output<ImmutableArray<Outputs.TargetTargetResponderRecipe>> TargetResponderRecipes { get; private set; } = null!;

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
        /// Create a Target resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Target(string name, TargetArgs args, CustomResourceOptions? options = null)
            : base("oci:cloudguard/target:Target", name, args ?? new TargetArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Target(string name, Input<string> id, TargetState? state = null, CustomResourceOptions? options = null)
            : base("oci:cloudguard/target:Target", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Target resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Target Get(string name, Input<string> id, TargetState? state = null, CustomResourceOptions? options = null)
        {
            return new Target(name, id, state, options);
        }
    }

    public sealed class TargetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) compartment associated with condition
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
        /// The target description.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) DetectorTemplate Identifier
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
        /// (Updatable) The current state of the DetectorRule.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("targetDetectorRecipes")]
        private InputList<Inputs.TargetTargetDetectorRecipeArgs>? _targetDetectorRecipes;

        /// <summary>
        /// (Updatable) List of detector recipes to associate with target
        /// </summary>
        public InputList<Inputs.TargetTargetDetectorRecipeArgs> TargetDetectorRecipes
        {
            get => _targetDetectorRecipes ?? (_targetDetectorRecipes = new InputList<Inputs.TargetTargetDetectorRecipeArgs>());
            set => _targetDetectorRecipes = value;
        }

        /// <summary>
        /// Resource ID which the target uses to monitor
        /// </summary>
        [Input("targetResourceId", required: true)]
        public Input<string> TargetResourceId { get; set; } = null!;

        /// <summary>
        /// possible type of targets(compartment/HCMCloud/ERPCloud)
        /// </summary>
        [Input("targetResourceType", required: true)]
        public Input<string> TargetResourceType { get; set; } = null!;

        [Input("targetResponderRecipes")]
        private InputList<Inputs.TargetTargetResponderRecipeArgs>? _targetResponderRecipes;

        /// <summary>
        /// (Updatable) List of responder recipes to associate with target
        /// </summary>
        public InputList<Inputs.TargetTargetResponderRecipeArgs> TargetResponderRecipes
        {
            get => _targetResponderRecipes ?? (_targetResponderRecipes = new InputList<Inputs.TargetTargetResponderRecipeArgs>());
            set => _targetResponderRecipes = value;
        }

        public TargetArgs()
        {
        }
    }

    public sealed class TargetState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) compartment associated with condition
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
        /// The target description.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) DetectorTemplate Identifier
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

        [Input("inheritedByCompartments")]
        private InputList<string>? _inheritedByCompartments;

        /// <summary>
        /// List of inherited compartments
        /// </summary>
        public InputList<string> InheritedByCompartments
        {
            get => _inheritedByCompartments ?? (_inheritedByCompartments = new InputList<string>());
            set => _inheritedByCompartments = value;
        }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecyleDetails")]
        public Input<string>? LifecyleDetails { get; set; }

        /// <summary>
        /// Total number of recipes attached to target
        /// </summary>
        [Input("recipeCount")]
        public Input<int>? RecipeCount { get; set; }

        /// <summary>
        /// (Updatable) The current state of the DetectorRule.
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

        [Input("targetDetectorRecipes")]
        private InputList<Inputs.TargetTargetDetectorRecipeGetArgs>? _targetDetectorRecipes;

        /// <summary>
        /// (Updatable) List of detector recipes to associate with target
        /// </summary>
        public InputList<Inputs.TargetTargetDetectorRecipeGetArgs> TargetDetectorRecipes
        {
            get => _targetDetectorRecipes ?? (_targetDetectorRecipes = new InputList<Inputs.TargetTargetDetectorRecipeGetArgs>());
            set => _targetDetectorRecipes = value;
        }

        /// <summary>
        /// Resource ID which the target uses to monitor
        /// </summary>
        [Input("targetResourceId")]
        public Input<string>? TargetResourceId { get; set; }

        /// <summary>
        /// possible type of targets(compartment/HCMCloud/ERPCloud)
        /// </summary>
        [Input("targetResourceType")]
        public Input<string>? TargetResourceType { get; set; }

        [Input("targetResponderRecipes")]
        private InputList<Inputs.TargetTargetResponderRecipeGetArgs>? _targetResponderRecipes;

        /// <summary>
        /// (Updatable) List of responder recipes to associate with target
        /// </summary>
        public InputList<Inputs.TargetTargetResponderRecipeGetArgs> TargetResponderRecipes
        {
            get => _targetResponderRecipes ?? (_targetResponderRecipes = new InputList<Inputs.TargetTargetResponderRecipeGetArgs>());
            set => _targetResponderRecipes = value;
        }

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

        public TargetState()
        {
        }
    }
}
