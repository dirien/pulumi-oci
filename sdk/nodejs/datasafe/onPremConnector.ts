// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the On Prem Connector resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Creates a new on-premises connector.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOnPremConnector = new oci.datasafe.OnPremConnector("testOnPremConnector", {
 *     compartmentId: _var.compartment_id,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: _var.on_prem_connector_description,
 *     displayName: _var.on_prem_connector_display_name,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * OnPremConnectors can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:datasafe/onPremConnector:OnPremConnector test_on_prem_connector "id"
 * ```
 */
export class OnPremConnector extends pulumi.CustomResource {
    /**
     * Get an existing OnPremConnector resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: OnPremConnectorState, opts?: pulumi.CustomResourceOptions): OnPremConnector {
        return new OnPremConnector(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:datasafe/onPremConnector:OnPremConnector';

    /**
     * Returns true if the given object is an instance of OnPremConnector.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is OnPremConnector {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === OnPremConnector.__pulumiType;
    }

    /**
     * Latest available version of the on-premises connector.
     */
    public /*out*/ readonly availableVersion!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the compartment where you want to create the on-premises connector.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * Created version of the on-premises connector.
     */
    public /*out*/ readonly createdVersion!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The description of the on-premises connector.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) The display name of the on-premises connector. The name does not have to be unique, and it's changeable.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Details about the current state of the on-premises connector.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The current state of the on-premises connector.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The date and time the on-premises connector was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a OnPremConnector resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: OnPremConnectorArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: OnPremConnectorArgs | OnPremConnectorState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as OnPremConnectorState | undefined;
            inputs["availableVersion"] = state ? state.availableVersion : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["createdVersion"] = state ? state.createdVersion : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["systemTags"] = state ? state.systemTags : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as OnPremConnectorArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["availableVersion"] = undefined /*out*/;
            inputs["createdVersion"] = undefined /*out*/;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["systemTags"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(OnPremConnector.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering OnPremConnector resources.
 */
export interface OnPremConnectorState {
    /**
     * Latest available version of the on-premises connector.
     */
    availableVersion?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the compartment where you want to create the on-premises connector.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Created version of the on-premises connector.
     */
    createdVersion?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The description of the on-premises connector.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the on-premises connector. The name does not have to be unique, and it's changeable.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Details about the current state of the on-premises connector.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The current state of the on-premises connector.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The date and time the on-premises connector was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a OnPremConnector resource.
 */
export interface OnPremConnectorArgs {
    /**
     * (Updatable) The OCID of the compartment where you want to create the on-premises connector.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The description of the on-premises connector.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the on-premises connector. The name does not have to be unique, and it's changeable.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
}
