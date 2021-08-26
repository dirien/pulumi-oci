// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Log Group resource in Oracle Cloud Infrastructure Logging service.
 *
 * Create a new log group with a unique display name. This call fails
 * if the log group is already created with the same displayName in the compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testLogGroup = new oci.logging.LogGroup("testLogGroup", {
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.log_group_display_name,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: _var.log_group_description,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * LogGroups can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:logging/logGroup:LogGroup test_log_group "id"
 * ```
 */
export class LogGroup extends pulumi.CustomResource {
    /**
     * Get an existing LogGroup resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: LogGroupState, opts?: pulumi.CustomResourceOptions): LogGroup {
        return new LogGroup(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:logging/logGroup:LogGroup';

    /**
     * Returns true if the given object is an instance of LogGroup.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is LogGroup {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === LogGroup.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the compartment that the resource belongs to.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Description for this resource.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The log group object state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Time the resource was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Time the resource was last modified.
     */
    public /*out*/ readonly timeLastModified!: pulumi.Output<string>;

    /**
     * Create a LogGroup resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: LogGroupArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: LogGroupArgs | LogGroupState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as LogGroupState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeLastModified"] = state ? state.timeLastModified : undefined;
        } else {
            const args = argsOrState as LogGroupArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeLastModified"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(LogGroup.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering LogGroup resources.
 */
export interface LogGroupState {
    /**
     * (Updatable) The OCID of the compartment that the resource belongs to.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Description for this resource.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The log group object state.
     */
    state?: pulumi.Input<string>;
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
 * The set of arguments for constructing a LogGroup resource.
 */
export interface LogGroupArgs {
    /**
     * (Updatable) The OCID of the compartment that the resource belongs to.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Description for this resource.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
}
