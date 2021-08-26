// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Quota resource in Oracle Cloud Infrastructure Limits service.
 *
 * Creates a new quota with the details supplied.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testQuota = new oci.limits.Quota("testQuota", {
 *     compartmentId: _var.tenancy_ocid,
 *     description: _var.quota_description,
 *     statements: _var.quota_statements,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * Quotas can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:limits/quota:Quota test_quota "id"
 * ```
 */
export class Quota extends pulumi.CustomResource {
    /**
     * Get an existing Quota resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: QuotaState, opts?: pulumi.CustomResourceOptions): Quota {
        return new Quota(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:limits/quota:Quota';

    /**
     * Returns true if the given object is an instance of Quota.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Quota {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Quota.__pulumiType;
    }

    /**
     * The OCID of the compartment containing the resource this quota applies to.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The description you assign to the quota.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The name you assign to the quota during creation. The name must be unique across all quotas in the tenancy and cannot be changed.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * The quota's current state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * (Updatable) An array of quota statements written in the declarative quota statement language.
     */
    public readonly statements!: pulumi.Output<string[]>;
    /**
     * Date and time the quota was created, in the format defined by RFC 3339. Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a Quota resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: QuotaArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: QuotaArgs | QuotaState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as QuotaState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["name"] = state ? state.name : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["statements"] = state ? state.statements : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as QuotaArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.description === undefined) && !opts.urn) {
                throw new Error("Missing required property 'description'");
            }
            if ((!args || args.statements === undefined) && !opts.urn) {
                throw new Error("Missing required property 'statements'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["name"] = args ? args.name : undefined;
            inputs["statements"] = args ? args.statements : undefined;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(Quota.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Quota resources.
 */
export interface QuotaState {
    /**
     * The OCID of the compartment containing the resource this quota applies to.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The description you assign to the quota.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The name you assign to the quota during creation. The name must be unique across all quotas in the tenancy and cannot be changed.
     */
    name?: pulumi.Input<string>;
    /**
     * The quota's current state.
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) An array of quota statements written in the declarative quota statement language.
     */
    statements?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Date and time the quota was created, in the format defined by RFC 3339. Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Quota resource.
 */
export interface QuotaArgs {
    /**
     * The OCID of the compartment containing the resource this quota applies to.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The description you assign to the quota.
     */
    description: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The name you assign to the quota during creation. The name must be unique across all quotas in the tenancy and cannot be changed.
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) An array of quota statements written in the declarative quota statement language.
     */
    statements: pulumi.Input<pulumi.Input<string>[]>;
}
