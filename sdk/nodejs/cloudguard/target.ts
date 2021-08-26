// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Target resource in Oracle Cloud Infrastructure Cloud Guard service.
 *
 * Creates a new Target
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTarget = new oci.cloudguard.Target("testTarget", {
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.target_display_name,
 *     targetResourceId: oci_cloud_guard_target_resource.test_target_resource.id,
 *     targetResourceType: _var.target_target_resource_type,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     description: _var.target_description,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     state: _var.target_state,
 *     targetDetectorRecipes: [{
 *         detectorRecipeId: oci_cloud_guard_detector_recipe.test_detector_recipe.id,
 *         detectorRules: [{
 *             details: {
 *                 conditionGroups: [{
 *                     compartmentId: _var.compartment_id,
 *                     condition: _var.target_target_detector_recipes_detector_rules_details_condition_groups_condition,
 *                 }],
 *             },
 *             detectorRuleId: oci_events_rule.test_rule.id,
 *         }],
 *     }],
 *     targetResponderRecipes: [{
 *         responderRecipeId: oci_cloud_guard_responder_recipe.test_responder_recipe.id,
 *         responderRules: [{
 *             details: {
 *                 condition: _var.target_target_responder_recipes_responder_rules_details_condition,
 *                 configurations: [{
 *                     configKey: _var.target_target_responder_recipes_responder_rules_details_configurations_config_key,
 *                     name: _var.target_target_responder_recipes_responder_rules_details_configurations_name,
 *                     value: _var.target_target_responder_recipes_responder_rules_details_configurations_value,
 *                 }],
 *                 mode: _var.target_target_responder_recipes_responder_rules_details_mode,
 *             },
 *             responderRuleId: oci_events_rule.test_rule.id,
 *         }],
 *     }],
 * });
 * ```
 *
 * ## Import
 *
 * Targets can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:cloudguard/target:Target test_target "id"
 * ```
 */
export class Target extends pulumi.CustomResource {
    /**
     * Get an existing Target resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: TargetState, opts?: pulumi.CustomResourceOptions): Target {
        return new Target(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:cloudguard/target:Target';

    /**
     * Returns true if the given object is an instance of Target.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Target {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Target.__pulumiType;
    }

    /**
     * (Updatable) compartment associated with condition
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The target description.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) DetectorTemplate Identifier
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * List of inherited compartments
     */
    public /*out*/ readonly inheritedByCompartments!: pulumi.Output<string[]>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecyleDetails!: pulumi.Output<string>;
    /**
     * Total number of recipes attached to target
     */
    public /*out*/ readonly recipeCount!: pulumi.Output<number>;
    /**
     * (Updatable) The current state of the DetectorRule.
     */
    public readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) List of detector recipes to associate with target
     */
    public readonly targetDetectorRecipes!: pulumi.Output<outputs.cloudguard.TargetTargetDetectorRecipe[]>;
    /**
     * Resource ID which the target uses to monitor
     */
    public readonly targetResourceId!: pulumi.Output<string>;
    /**
     * possible type of targets(compartment/HCMCloud/ERPCloud)
     */
    public readonly targetResourceType!: pulumi.Output<string>;
    /**
     * (Updatable) List of responder recipes to associate with target
     */
    public readonly targetResponderRecipes!: pulumi.Output<outputs.cloudguard.TargetTargetResponderRecipe[]>;
    /**
     * The date and time the target was created. Format defined by RFC3339.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the target was updated. Format defined by RFC3339.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a Target resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: TargetArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: TargetArgs | TargetState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as TargetState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["inheritedByCompartments"] = state ? state.inheritedByCompartments : undefined;
            inputs["lifecyleDetails"] = state ? state.lifecyleDetails : undefined;
            inputs["recipeCount"] = state ? state.recipeCount : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["systemTags"] = state ? state.systemTags : undefined;
            inputs["targetDetectorRecipes"] = state ? state.targetDetectorRecipes : undefined;
            inputs["targetResourceId"] = state ? state.targetResourceId : undefined;
            inputs["targetResourceType"] = state ? state.targetResourceType : undefined;
            inputs["targetResponderRecipes"] = state ? state.targetResponderRecipes : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as TargetArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.targetResourceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'targetResourceId'");
            }
            if ((!args || args.targetResourceType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'targetResourceType'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["state"] = args ? args.state : undefined;
            inputs["targetDetectorRecipes"] = args ? args.targetDetectorRecipes : undefined;
            inputs["targetResourceId"] = args ? args.targetResourceId : undefined;
            inputs["targetResourceType"] = args ? args.targetResourceType : undefined;
            inputs["targetResponderRecipes"] = args ? args.targetResponderRecipes : undefined;
            inputs["inheritedByCompartments"] = undefined /*out*/;
            inputs["lifecyleDetails"] = undefined /*out*/;
            inputs["recipeCount"] = undefined /*out*/;
            inputs["systemTags"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeUpdated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(Target.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Target resources.
 */
export interface TargetState {
    /**
     * (Updatable) compartment associated with condition
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The target description.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) DetectorTemplate Identifier
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * List of inherited compartments
     */
    inheritedByCompartments?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecyleDetails?: pulumi.Input<string>;
    /**
     * Total number of recipes attached to target
     */
    recipeCount?: pulumi.Input<number>;
    /**
     * (Updatable) The current state of the DetectorRule.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) List of detector recipes to associate with target
     */
    targetDetectorRecipes?: pulumi.Input<pulumi.Input<inputs.cloudguard.TargetTargetDetectorRecipe>[]>;
    /**
     * Resource ID which the target uses to monitor
     */
    targetResourceId?: pulumi.Input<string>;
    /**
     * possible type of targets(compartment/HCMCloud/ERPCloud)
     */
    targetResourceType?: pulumi.Input<string>;
    /**
     * (Updatable) List of responder recipes to associate with target
     */
    targetResponderRecipes?: pulumi.Input<pulumi.Input<inputs.cloudguard.TargetTargetResponderRecipe>[]>;
    /**
     * The date and time the target was created. Format defined by RFC3339.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the target was updated. Format defined by RFC3339.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Target resource.
 */
export interface TargetArgs {
    /**
     * (Updatable) compartment associated with condition
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The target description.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) DetectorTemplate Identifier
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The current state of the DetectorRule.
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) List of detector recipes to associate with target
     */
    targetDetectorRecipes?: pulumi.Input<pulumi.Input<inputs.cloudguard.TargetTargetDetectorRecipe>[]>;
    /**
     * Resource ID which the target uses to monitor
     */
    targetResourceId: pulumi.Input<string>;
    /**
     * possible type of targets(compartment/HCMCloud/ERPCloud)
     */
    targetResourceType: pulumi.Input<string>;
    /**
     * (Updatable) List of responder recipes to associate with target
     */
    targetResponderRecipes?: pulumi.Input<pulumi.Input<inputs.cloudguard.TargetTargetResponderRecipe>[]>;
}
