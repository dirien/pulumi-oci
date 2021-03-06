// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Log resource in Oracle Cloud Infrastructure Logging service.
 *
 * Creates a log within the specified log group. This call fails if a log group has already been created
 * with the same displayName or (service, resource, category) triplet.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testLog = new oci.logging.Log("testLog", {
 *     displayName: _var.log_display_name,
 *     logGroupId: oci_logging_log_group.test_log_group.id,
 *     logType: _var.log_log_type,
 *     configuration: {
 *         source: {
 *             category: _var.log_configuration_source_category,
 *             resource: _var.log_configuration_source_resource,
 *             service: _var.log_configuration_source_service,
 *             sourceType: _var.log_configuration_source_source_type,
 *         },
 *         compartmentId: _var.compartment_id,
 *     },
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     isEnabled: _var.log_is_enabled,
 *     retentionDuration: _var.log_retention_duration,
 * });
 * ```
 *
 * ## Import
 *
 * Logs can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:logging/log:Log test_log "logGroupId/{logGroupId}/logId/{logId}"
 * ```
 */
export class Log extends pulumi.CustomResource {
    /**
     * Get an existing Log resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: LogState, opts?: pulumi.CustomResourceOptions): Log {
        return new Log(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:logging/log:Log';

    /**
     * Returns true if the given object is an instance of Log.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Log {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Log.__pulumiType;
    }

    /**
     * The OCID of the compartment that the resource belongs to.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * Log object configuration.
     */
    public readonly configuration!: pulumi.Output<outputs.logging.LogConfiguration>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Whether or not this resource is currently enabled.
     */
    public readonly isEnabled!: pulumi.Output<boolean>;
    /**
     * (Updatable) OCID of a log group to work with.
     */
    public readonly logGroupId!: pulumi.Output<string>;
    /**
     * The logType that the log object is for, whether custom or service.
     */
    public readonly logType!: pulumi.Output<string>;
    /**
     * (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on).
     */
    public readonly retentionDuration!: pulumi.Output<number>;
    /**
     * The pipeline state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The OCID of the tenancy.
     */
    public /*out*/ readonly tenancyId!: pulumi.Output<string>;
    /**
     * Time the resource was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Time the resource was last modified.
     */
    public /*out*/ readonly timeLastModified!: pulumi.Output<string>;

    /**
     * Create a Log resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: LogArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: LogArgs | LogState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as LogState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["configuration"] = state ? state.configuration : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["isEnabled"] = state ? state.isEnabled : undefined;
            inputs["logGroupId"] = state ? state.logGroupId : undefined;
            inputs["logType"] = state ? state.logType : undefined;
            inputs["retentionDuration"] = state ? state.retentionDuration : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["tenancyId"] = state ? state.tenancyId : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeLastModified"] = state ? state.timeLastModified : undefined;
        } else {
            const args = argsOrState as LogArgs | undefined;
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.logGroupId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'logGroupId'");
            }
            if ((!args || args.logType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'logType'");
            }
            inputs["configuration"] = args ? args.configuration : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["isEnabled"] = args ? args.isEnabled : undefined;
            inputs["logGroupId"] = args ? args.logGroupId : undefined;
            inputs["logType"] = args ? args.logType : undefined;
            inputs["retentionDuration"] = args ? args.retentionDuration : undefined;
            inputs["compartmentId"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["tenancyId"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeLastModified"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(Log.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Log resources.
 */
export interface LogState {
    /**
     * The OCID of the compartment that the resource belongs to.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Log object configuration.
     */
    configuration?: pulumi.Input<inputs.logging.LogConfiguration>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Whether or not this resource is currently enabled.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) OCID of a log group to work with.
     */
    logGroupId?: pulumi.Input<string>;
    /**
     * The logType that the log object is for, whether custom or service.
     */
    logType?: pulumi.Input<string>;
    /**
     * (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on).
     */
    retentionDuration?: pulumi.Input<number>;
    /**
     * The pipeline state.
     */
    state?: pulumi.Input<string>;
    /**
     * The OCID of the tenancy.
     */
    tenancyId?: pulumi.Input<string>;
    /**
     * Time the resource was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * Time the resource was last modified.
     */
    timeLastModified?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Log resource.
 */
export interface LogArgs {
    /**
     * Log object configuration.
     */
    configuration?: pulumi.Input<inputs.logging.LogConfiguration>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Whether or not this resource is currently enabled.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) OCID of a log group to work with.
     */
    logGroupId: pulumi.Input<string>;
    /**
     * The logType that the log object is for, whether custom or service.
     */
    logType: pulumi.Input<string>;
    /**
     * (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on).
     */
    retentionDuration?: pulumi.Input<number>;
}
