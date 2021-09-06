// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Management Agent Install Key resource in Oracle Cloud Infrastructure Management Agent service.
 *
 * User creates a new install key as part of this API.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagementAgentInstallKey = new oci.managementagent.ManagementAgentInstallKey("testManagementAgentInstallKey", {
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.management_agent_install_key_display_name,
 *     allowedKeyInstallCount: _var.management_agent_install_key_allowed_key_install_count,
 *     timeExpires: _var.management_agent_install_key_time_expires,
 * });
 * ```
 *
 * ## Import
 *
 * ManagementAgentInstallKeys can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:managementagent/managementAgentInstallKey:ManagementAgentInstallKey test_management_agent_install_key "id"
 * ```
 */
export class ManagementAgentInstallKey extends pulumi.CustomResource {
    /**
     * Get an existing ManagementAgentInstallKey resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ManagementAgentInstallKeyState, opts?: pulumi.CustomResourceOptions): ManagementAgentInstallKey {
        return new ManagementAgentInstallKey(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:managementagent/managementAgentInstallKey:ManagementAgentInstallKey';

    /**
     * Returns true if the given object is an instance of ManagementAgentInstallKey.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ManagementAgentInstallKey {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ManagementAgentInstallKey.__pulumiType;
    }

    /**
     * Total number of install for this keys
     */
    public readonly allowedKeyInstallCount!: pulumi.Output<number>;
    /**
     * Compartment Identifier
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * Principal id of user who created the Agent Install key
     */
    public /*out*/ readonly createdByPrincipalId!: pulumi.Output<string>;
    /**
     * Total number of install for this keys
     */
    public /*out*/ readonly currentKeyInstallCount!: pulumi.Output<number>;
    /**
     * (Updatable) Management Agent install Key Name
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Management Agent Install Key
     */
    public /*out*/ readonly key!: pulumi.Output<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * Status of Key
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The time when Management Agent install Key was created. An RFC3339 formatted date time string
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * date after which key would expire after creation
     */
    public readonly timeExpires!: pulumi.Output<string>;
    /**
     * The time when Management Agent install Key was updated. An RFC3339 formatted date time string
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a ManagementAgentInstallKey resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ManagementAgentInstallKeyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ManagementAgentInstallKeyArgs | ManagementAgentInstallKeyState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ManagementAgentInstallKeyState | undefined;
            inputs["allowedKeyInstallCount"] = state ? state.allowedKeyInstallCount : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["createdByPrincipalId"] = state ? state.createdByPrincipalId : undefined;
            inputs["currentKeyInstallCount"] = state ? state.currentKeyInstallCount : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["key"] = state ? state.key : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeExpires"] = state ? state.timeExpires : undefined;
            inputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as ManagementAgentInstallKeyArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            inputs["allowedKeyInstallCount"] = args ? args.allowedKeyInstallCount : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["timeExpires"] = args ? args.timeExpires : undefined;
            inputs["createdByPrincipalId"] = undefined /*out*/;
            inputs["currentKeyInstallCount"] = undefined /*out*/;
            inputs["key"] = undefined /*out*/;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeUpdated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(ManagementAgentInstallKey.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ManagementAgentInstallKey resources.
 */
export interface ManagementAgentInstallKeyState {
    /**
     * Total number of install for this keys
     */
    allowedKeyInstallCount?: pulumi.Input<number>;
    /**
     * Compartment Identifier
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Principal id of user who created the Agent Install key
     */
    createdByPrincipalId?: pulumi.Input<string>;
    /**
     * Total number of install for this keys
     */
    currentKeyInstallCount?: pulumi.Input<number>;
    /**
     * (Updatable) Management Agent install Key Name
     */
    displayName?: pulumi.Input<string>;
    /**
     * Management Agent Install Key
     */
    key?: pulumi.Input<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * Status of Key
     */
    state?: pulumi.Input<string>;
    /**
     * The time when Management Agent install Key was created. An RFC3339 formatted date time string
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * date after which key would expire after creation
     */
    timeExpires?: pulumi.Input<string>;
    /**
     * The time when Management Agent install Key was updated. An RFC3339 formatted date time string
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ManagementAgentInstallKey resource.
 */
export interface ManagementAgentInstallKeyArgs {
    /**
     * Total number of install for this keys
     */
    allowedKeyInstallCount?: pulumi.Input<number>;
    /**
     * Compartment Identifier
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Management Agent install Key Name
     */
    displayName: pulumi.Input<string>;
    /**
     * date after which key would expire after creation
     */
    timeExpires?: pulumi.Input<string>;
}
