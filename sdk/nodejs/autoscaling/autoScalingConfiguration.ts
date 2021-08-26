// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Auto Scaling Configuration resource in Oracle Cloud Infrastructure Auto Scaling service.
 *
 * Creates an autoscaling configuration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutoScalingConfiguration = new oci.autoscaling.AutoScalingConfiguration("testAutoScalingConfiguration", {
 *     autoScalingResources: {
 *         id: _var.auto_scaling_configuration_auto_scaling_resources_id,
 *         type: _var.auto_scaling_configuration_auto_scaling_resources_type,
 *     },
 *     compartmentId: _var.compartment_id,
 *     policies: [{
 *         policyType: _var.auto_scaling_configuration_policies_policy_type,
 *         capacity: {
 *             initial: _var.auto_scaling_configuration_policies_capacity_initial,
 *             max: _var.auto_scaling_configuration_policies_capacity_max,
 *             min: _var.auto_scaling_configuration_policies_capacity_min,
 *         },
 *         displayName: _var.auto_scaling_configuration_policies_display_name,
 *         executionSchedule: {
 *             expression: _var.auto_scaling_configuration_policies_execution_schedule_expression,
 *             timezone: _var.auto_scaling_configuration_policies_execution_schedule_timezone,
 *             type: _var.auto_scaling_configuration_policies_execution_schedule_type,
 *         },
 *         isEnabled: _var.auto_scaling_configuration_policies_is_enabled,
 *         resourceAction: {
 *             action: _var.auto_scaling_configuration_policies_resource_action_action,
 *             actionType: _var.auto_scaling_configuration_policies_resource_action_action_type,
 *         },
 *         rules: [{
 *             action: {
 *                 type: _var.auto_scaling_configuration_policies_rules_action_type,
 *                 value: _var.auto_scaling_configuration_policies_rules_action_value,
 *             },
 *             displayName: _var.auto_scaling_configuration_policies_rules_display_name,
 *             metric: {
 *                 metricType: _var.auto_scaling_configuration_policies_rules_metric_metric_type,
 *                 threshold: {
 *                     operator: _var.auto_scaling_configuration_policies_rules_metric_threshold_operator,
 *                     value: _var.auto_scaling_configuration_policies_rules_metric_threshold_value,
 *                 },
 *             },
 *         }],
 *     }],
 *     coolDownInSeconds: _var.auto_scaling_configuration_cool_down_in_seconds,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: _var.auto_scaling_configuration_display_name,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     isEnabled: _var.auto_scaling_configuration_is_enabled,
 * });
 * ```
 *
 * ## Import
 *
 * AutoScalingConfigurations can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:autoscaling/autoScalingConfiguration:AutoScalingConfiguration test_auto_scaling_configuration "id"
 * ```
 */
export class AutoScalingConfiguration extends pulumi.CustomResource {
    /**
     * Get an existing AutoScalingConfiguration resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AutoScalingConfigurationState, opts?: pulumi.CustomResourceOptions): AutoScalingConfiguration {
        return new AutoScalingConfiguration(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:autoscaling/autoScalingConfiguration:AutoScalingConfiguration';

    /**
     * Returns true if the given object is an instance of AutoScalingConfiguration.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AutoScalingConfiguration {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AutoScalingConfiguration.__pulumiType;
    }

    /**
     * A resource that is managed by an autoscaling configuration. The only supported type is `instancePool`.
     */
    public readonly autoScalingResources!: pulumi.Output<outputs.autoscaling.AutoScalingConfigurationAutoScalingResources>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the autoscaling configuration.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) For threshold-based autoscaling policies, this value is the minimum period of time to wait between scaling actions. The cooldown period gives the system time to stabilize before rescaling. The minimum value is 300 seconds, which is also the default. The cooldown period starts when the instance pool reaches the running state.
     */
    public readonly coolDownInSeconds!: pulumi.Output<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Whether the autoscaling policy is enabled.
     */
    public readonly isEnabled!: pulumi.Output<boolean>;
    /**
     * The maximum number of resources to scale out to.
     */
    public /*out*/ readonly maxResourceCount!: pulumi.Output<number>;
    /**
     * The minimum number of resources to scale in to.
     */
    public /*out*/ readonly minResourceCount!: pulumi.Output<number>;
    /**
     * Autoscaling policy definitions for the autoscaling configuration. An autoscaling policy defines the criteria that trigger autoscaling actions and the actions to take.
     */
    public readonly policies!: pulumi.Output<outputs.autoscaling.AutoScalingConfigurationPolicy[]>;
    /**
     * The date and time the autoscaling configuration was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a AutoScalingConfiguration resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AutoScalingConfigurationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AutoScalingConfigurationArgs | AutoScalingConfigurationState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AutoScalingConfigurationState | undefined;
            inputs["autoScalingResources"] = state ? state.autoScalingResources : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["coolDownInSeconds"] = state ? state.coolDownInSeconds : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["isEnabled"] = state ? state.isEnabled : undefined;
            inputs["maxResourceCount"] = state ? state.maxResourceCount : undefined;
            inputs["minResourceCount"] = state ? state.minResourceCount : undefined;
            inputs["policies"] = state ? state.policies : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as AutoScalingConfigurationArgs | undefined;
            if ((!args || args.autoScalingResources === undefined) && !opts.urn) {
                throw new Error("Missing required property 'autoScalingResources'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.policies === undefined) && !opts.urn) {
                throw new Error("Missing required property 'policies'");
            }
            inputs["autoScalingResources"] = args ? args.autoScalingResources : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["coolDownInSeconds"] = args ? args.coolDownInSeconds : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["isEnabled"] = args ? args.isEnabled : undefined;
            inputs["policies"] = args ? args.policies : undefined;
            inputs["maxResourceCount"] = undefined /*out*/;
            inputs["minResourceCount"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(AutoScalingConfiguration.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AutoScalingConfiguration resources.
 */
export interface AutoScalingConfigurationState {
    /**
     * A resource that is managed by an autoscaling configuration. The only supported type is `instancePool`.
     */
    autoScalingResources?: pulumi.Input<inputs.autoscaling.AutoScalingConfigurationAutoScalingResources>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the autoscaling configuration.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) For threshold-based autoscaling policies, this value is the minimum period of time to wait between scaling actions. The cooldown period gives the system time to stabilize before rescaling. The minimum value is 300 seconds, which is also the default. The cooldown period starts when the instance pool reaches the running state.
     */
    coolDownInSeconds?: pulumi.Input<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Whether the autoscaling policy is enabled.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * The maximum number of resources to scale out to.
     */
    maxResourceCount?: pulumi.Input<number>;
    /**
     * The minimum number of resources to scale in to.
     */
    minResourceCount?: pulumi.Input<number>;
    /**
     * Autoscaling policy definitions for the autoscaling configuration. An autoscaling policy defines the criteria that trigger autoscaling actions and the actions to take.
     */
    policies?: pulumi.Input<pulumi.Input<inputs.autoscaling.AutoScalingConfigurationPolicy>[]>;
    /**
     * The date and time the autoscaling configuration was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AutoScalingConfiguration resource.
 */
export interface AutoScalingConfigurationArgs {
    /**
     * A resource that is managed by an autoscaling configuration. The only supported type is `instancePool`.
     */
    autoScalingResources: pulumi.Input<inputs.autoscaling.AutoScalingConfigurationAutoScalingResources>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the autoscaling configuration.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) For threshold-based autoscaling policies, this value is the minimum period of time to wait between scaling actions. The cooldown period gives the system time to stabilize before rescaling. The minimum value is 300 seconds, which is also the default. The cooldown period starts when the instance pool reaches the running state.
     */
    coolDownInSeconds?: pulumi.Input<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Whether the autoscaling policy is enabled.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * Autoscaling policy definitions for the autoscaling configuration. An autoscaling policy defines the criteria that trigger autoscaling actions and the actions to take.
     */
    policies: pulumi.Input<pulumi.Input<inputs.autoscaling.AutoScalingConfigurationPolicy>[]>;
}
