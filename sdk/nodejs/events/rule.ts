// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Rule resource in Oracle Cloud Infrastructure Events service.
 *
 * Creates a new rule.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRule = new oci.events.Rule("testRule", {
 *     actions: {
 *         actions: [{
 *             actionType: _var.rule_actions_actions_action_type,
 *             isEnabled: _var.rule_actions_actions_is_enabled,
 *             description: _var.rule_actions_actions_description,
 *             functionId: oci_functions_function.test_function.id,
 *             streamId: oci_streaming_stream.test_stream.id,
 *             topicId: oci_ons_notification_topic.test_topic.id,
 *         }],
 *     },
 *     compartmentId: _var.compartment_id,
 *     condition: _var.rule_condition,
 *     displayName: _var.rule_display_name,
 *     isEnabled: _var.rule_is_enabled,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: _var.rule_description,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * Rules can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:events/rule:Rule test_rule "id"
 * ```
 */
export class Rule extends pulumi.CustomResource {
    /**
     * Get an existing Rule resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: RuleState, opts?: pulumi.CustomResourceOptions): Rule {
        return new Rule(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:events/rule:Rule';

    /**
     * Returns true if the given object is an instance of Rule.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Rule {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Rule.__pulumiType;
    }

    /**
     * (Updatable) A list of one or more ActionDetails objects.
     */
    public readonly actions!: pulumi.Output<outputs.events.RuleActions>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
     * * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
     */
    public readonly condition!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Whether or not this rule is currently enabled.  Example: `true`
     */
    public readonly isEnabled!: pulumi.Output<boolean>;
    /**
     * A message generated by the Events service about the current state of this rule.
     */
    public /*out*/ readonly lifecycleMessage!: pulumi.Output<string>;
    /**
     * The current state of the rule.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The time this rule was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a Rule resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: RuleArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: RuleArgs | RuleState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as RuleState | undefined;
            inputs["actions"] = state ? state.actions : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["condition"] = state ? state.condition : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["isEnabled"] = state ? state.isEnabled : undefined;
            inputs["lifecycleMessage"] = state ? state.lifecycleMessage : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as RuleArgs | undefined;
            if ((!args || args.actions === undefined) && !opts.urn) {
                throw new Error("Missing required property 'actions'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.condition === undefined) && !opts.urn) {
                throw new Error("Missing required property 'condition'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.isEnabled === undefined) && !opts.urn) {
                throw new Error("Missing required property 'isEnabled'");
            }
            inputs["actions"] = args ? args.actions : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["condition"] = args ? args.condition : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["isEnabled"] = args ? args.isEnabled : undefined;
            inputs["lifecycleMessage"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(Rule.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Rule resources.
 */
export interface RuleState {
    /**
     * (Updatable) A list of one or more ActionDetails objects.
     */
    actions?: pulumi.Input<inputs.events.RuleActions>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
     * * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
     */
    condition?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Whether or not this rule is currently enabled.  Example: `true`
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * A message generated by the Events service about the current state of this rule.
     */
    lifecycleMessage?: pulumi.Input<string>;
    /**
     * The current state of the rule.
     */
    state?: pulumi.Input<string>;
    /**
     * The time this rule was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Rule resource.
 */
export interface RuleArgs {
    /**
     * (Updatable) A list of one or more ActionDetails objects.
     */
    actions: pulumi.Input<inputs.events.RuleActions>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
     * * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
     */
    condition: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Whether or not this rule is currently enabled.  Example: `true`
     */
    isEnabled: pulumi.Input<boolean>;
}
