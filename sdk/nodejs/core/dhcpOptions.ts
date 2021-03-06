// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Dhcp Options resource in Oracle Cloud Infrastructure Core service.
 *
 * Creates a new set of DHCP options for the specified VCN. For more information, see
 * [DhcpOptions](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/DhcpOptions/).
 *
 * For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want the set of
 * DHCP options to reside. Notice that the set of options doesn't have to be in the same compartment as the VCN,
 * subnets, or other Networking Service components. If you're not sure which compartment to use, put the set
 * of DHCP options in the same compartment as the VCN. For more information about compartments and access control, see
 * [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm). For information about OCIDs, see
 * [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * You may optionally specify a *display name* for the set of DHCP options, otherwise a default is provided.
 * It does not have to be unique, and you can change it. Avoid entering confidential information.
 *
 * For more information on configuring a VCN's default DHCP options, see [Managing Default VCN Resources](https://www.terraform.io/docs/providers/oci/guides/managing_default_resources.html)
 *
 * ## Example Usage
 *
 * ## Import
 *
 * DhcpOptions can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:core/dhcpOptions:DhcpOptions test_dhcp_options "id"
 * ```
 */
export class DhcpOptions extends pulumi.CustomResource {
    /**
     * Get an existing DhcpOptions resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DhcpOptionsState, opts?: pulumi.CustomResourceOptions): DhcpOptions {
        return new DhcpOptions(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:core/dhcpOptions:DhcpOptions';

    /**
     * Returns true if the given object is an instance of DhcpOptions.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DhcpOptions {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DhcpOptions.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the compartment to contain the set of DHCP options.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) The search domain name type of DHCP options
     */
    public readonly domainNameType!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A set of DHCP options.
     */
    public readonly options!: pulumi.Output<outputs.core.DhcpOptionsOption[]>;
    /**
     * The current state of the set of DHCP options.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Date and time the set of DHCP options was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The OCID of the VCN the set of DHCP options belongs to.
     */
    public readonly vcnId!: pulumi.Output<string>;

    /**
     * Create a DhcpOptions resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DhcpOptionsArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DhcpOptionsArgs | DhcpOptionsState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DhcpOptionsState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["domainNameType"] = state ? state.domainNameType : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["options"] = state ? state.options : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["vcnId"] = state ? state.vcnId : undefined;
        } else {
            const args = argsOrState as DhcpOptionsArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.options === undefined) && !opts.urn) {
                throw new Error("Missing required property 'options'");
            }
            if ((!args || args.vcnId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'vcnId'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["domainNameType"] = args ? args.domainNameType : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["options"] = args ? args.options : undefined;
            inputs["vcnId"] = args ? args.vcnId : undefined;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(DhcpOptions.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DhcpOptions resources.
 */
export interface DhcpOptionsState {
    /**
     * (Updatable) The OCID of the compartment to contain the set of DHCP options.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) The search domain name type of DHCP options
     */
    domainNameType?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A set of DHCP options.
     */
    options?: pulumi.Input<pulumi.Input<inputs.core.DhcpOptionsOption>[]>;
    /**
     * The current state of the set of DHCP options.
     */
    state?: pulumi.Input<string>;
    /**
     * Date and time the set of DHCP options was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The OCID of the VCN the set of DHCP options belongs to.
     */
    vcnId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DhcpOptions resource.
 */
export interface DhcpOptionsArgs {
    /**
     * (Updatable) The OCID of the compartment to contain the set of DHCP options.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) The search domain name type of DHCP options
     */
    domainNameType?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A set of DHCP options.
     */
    options: pulumi.Input<pulumi.Input<inputs.core.DhcpOptionsOption>[]>;
    /**
     * The OCID of the VCN the set of DHCP options belongs to.
     */
    vcnId: pulumi.Input<string>;
}
