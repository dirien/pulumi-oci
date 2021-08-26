// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Network Source resource in Oracle Cloud Infrastructure Identity service.
 *
 * Creates a new network source in your tenancy.
 *
 * You must specify your tenancy's OCID as the compartment ID in the request object (remember that the tenancy
 * is simply the root compartment). Notice that IAM resources (users, groups, compartments, and some policies)
 * reside within the tenancy itself, unlike cloud resources such as compute instances, which typically
 * reside within compartments inside the tenancy. For information about OCIDs, see
 * [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * You must also specify a *name* for the network source, which must be unique across all network sources in your
 * tenancy, and cannot be changed.
 * You can use this name or the OCID when writing policies that apply to the network source. For more information
 * about policies, see [How Policies Work](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policies.htm).
 *
 * You must also specify a *description* for the network source (although it can be an empty string). It does not
 * have to be unique, and you can change it anytime with [UpdateNetworkSource](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/NetworkSource/UpdateNetworkSource).
 * After your network resource is created, you can use it in policy to restrict access to only requests made from an allowed
 * IP address specified in your network source. For more information, see [Managing Network Sources](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingnetworksources.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNetworkSource = new oci.identity.NetworkSource("testNetworkSource", {
 *     compartmentId: _var.tenancy_ocid,
 *     description: _var.network_source_description,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     publicSourceLists: _var.network_source_public_source_list,
 *     services: _var.network_source_services,
 *     virtualSourceLists: _var.network_source_virtual_source_list,
 * });
 * ```
 *
 * ## Import
 *
 * NetworkSources can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:identity/networkSource:NetworkSource test_network_source "id"
 * ```
 */
export class NetworkSource extends pulumi.CustomResource {
    /**
     * Get an existing NetworkSource resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: NetworkSourceState, opts?: pulumi.CustomResourceOptions): NetworkSource {
        return new NetworkSource(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:identity/networkSource:NetworkSource';

    /**
     * Returns true if the given object is an instance of NetworkSource.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is NetworkSource {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === NetworkSource.__pulumiType;
    }

    /**
     * The OCID of the tenancy (root compartment) containing the network source object.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it's changeable.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    public /*out*/ readonly inactiveState!: pulumi.Output<string>;
    /**
     * The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * (Updatable) A list of allowed public IP addresses and CIDR ranges.
     */
    public readonly publicSourceLists!: pulumi.Output<string[]>;
    /**
     * (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
     */
    public readonly services!: pulumi.Output<string[]>;
    /**
     * The network source object's current state. After creating a network source, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`"vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID", "ipRanges": [ "129.213.39.0/24" ]`
     */
    public readonly virtualSourceLists!: pulumi.Output<outputs.identity.NetworkSourceVirtualSourceList[]>;

    /**
     * Create a NetworkSource resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: NetworkSourceArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: NetworkSourceArgs | NetworkSourceState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as NetworkSourceState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["inactiveState"] = state ? state.inactiveState : undefined;
            inputs["name"] = state ? state.name : undefined;
            inputs["publicSourceLists"] = state ? state.publicSourceLists : undefined;
            inputs["services"] = state ? state.services : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["virtualSourceLists"] = state ? state.virtualSourceLists : undefined;
        } else {
            const args = argsOrState as NetworkSourceArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.description === undefined) && !opts.urn) {
                throw new Error("Missing required property 'description'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["name"] = args ? args.name : undefined;
            inputs["publicSourceLists"] = args ? args.publicSourceLists : undefined;
            inputs["services"] = args ? args.services : undefined;
            inputs["virtualSourceLists"] = args ? args.virtualSourceLists : undefined;
            inputs["inactiveState"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(NetworkSource.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering NetworkSource resources.
 */
export interface NetworkSourceState {
    /**
     * The OCID of the tenancy (root compartment) containing the network source object.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it's changeable.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    inactiveState?: pulumi.Input<string>;
    /**
     * The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) A list of allowed public IP addresses and CIDR ranges.
     */
    publicSourceLists?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
     */
    services?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The network source object's current state. After creating a network source, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
     */
    state?: pulumi.Input<string>;
    /**
     * Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`"vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID", "ipRanges": [ "129.213.39.0/24" ]`
     */
    virtualSourceLists?: pulumi.Input<pulumi.Input<inputs.identity.NetworkSourceVirtualSourceList>[]>;
}

/**
 * The set of arguments for constructing a NetworkSource resource.
 */
export interface NetworkSourceArgs {
    /**
     * The OCID of the tenancy (root compartment) containing the network source object.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it's changeable.
     */
    description: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) A list of allowed public IP addresses and CIDR ranges.
     */
    publicSourceLists?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
     */
    services?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`"vcnId": "ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID", "ipRanges": [ "129.213.39.0/24" ]`
     */
    virtualSourceLists?: pulumi.Input<pulumi.Input<inputs.identity.NetworkSourceVirtualSourceList>[]>;
}