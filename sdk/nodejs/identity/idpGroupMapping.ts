// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Idp Group Mapping resource in Oracle Cloud Infrastructure Identity service.
 *
 * Creates a single mapping between an IdP group and an IAM Service
 * [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testIdpGroupMapping = new oci.identity.IdpGroupMapping("testIdpGroupMapping", {
 *     groupId: oci_identity_group.test_group.id,
 *     identityProviderId: oci_identity_identity_provider.test_identity_provider.id,
 *     idpGroupName: _var.idp_group_mapping_idp_group_name,
 * });
 * ```
 *
 * ## Import
 *
 * IdpGroupMappings can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:identity/idpGroupMapping:IdpGroupMapping test_idp_group_mapping "identityProviders/{identityProviderId}/groupMappings/{mappingId}"
 * ```
 */
export class IdpGroupMapping extends pulumi.CustomResource {
    /**
     * Get an existing IdpGroupMapping resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: IdpGroupMappingState, opts?: pulumi.CustomResourceOptions): IdpGroupMapping {
        return new IdpGroupMapping(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:identity/idpGroupMapping:IdpGroupMapping';

    /**
     * Returns true if the given object is an instance of IdpGroupMapping.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is IdpGroupMapping {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === IdpGroupMapping.__pulumiType;
    }

    /**
     * The OCID of the tenancy containing the `IdentityProvider`.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
     */
    public readonly groupId!: pulumi.Output<string>;
    /**
     * The OCID of the identity provider.
     */
    public readonly identityProviderId!: pulumi.Output<string>;
    /**
     * (Updatable) The name of the IdP group you want to map.
     */
    public readonly idpGroupName!: pulumi.Output<string>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    public /*out*/ readonly inactiveState!: pulumi.Output<string>;
    /**
     * The mapping's current state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Date and time the mapping was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a IdpGroupMapping resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: IdpGroupMappingArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: IdpGroupMappingArgs | IdpGroupMappingState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as IdpGroupMappingState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["groupId"] = state ? state.groupId : undefined;
            inputs["identityProviderId"] = state ? state.identityProviderId : undefined;
            inputs["idpGroupName"] = state ? state.idpGroupName : undefined;
            inputs["inactiveState"] = state ? state.inactiveState : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as IdpGroupMappingArgs | undefined;
            if ((!args || args.groupId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'groupId'");
            }
            if ((!args || args.identityProviderId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'identityProviderId'");
            }
            if ((!args || args.idpGroupName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'idpGroupName'");
            }
            inputs["groupId"] = args ? args.groupId : undefined;
            inputs["identityProviderId"] = args ? args.identityProviderId : undefined;
            inputs["idpGroupName"] = args ? args.idpGroupName : undefined;
            inputs["compartmentId"] = undefined /*out*/;
            inputs["inactiveState"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(IdpGroupMapping.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering IdpGroupMapping resources.
 */
export interface IdpGroupMappingState {
    /**
     * The OCID of the tenancy containing the `IdentityProvider`.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
     */
    groupId?: pulumi.Input<string>;
    /**
     * The OCID of the identity provider.
     */
    identityProviderId?: pulumi.Input<string>;
    /**
     * (Updatable) The name of the IdP group you want to map.
     */
    idpGroupName?: pulumi.Input<string>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    inactiveState?: pulumi.Input<string>;
    /**
     * The mapping's current state.
     */
    state?: pulumi.Input<string>;
    /**
     * Date and time the mapping was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a IdpGroupMapping resource.
 */
export interface IdpGroupMappingArgs {
    /**
     * (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
     */
    groupId: pulumi.Input<string>;
    /**
     * The OCID of the identity provider.
     */
    identityProviderId: pulumi.Input<string>;
    /**
     * (Updatable) The name of the IdP group you want to map.
     */
    idpGroupName: pulumi.Input<string>;
}
