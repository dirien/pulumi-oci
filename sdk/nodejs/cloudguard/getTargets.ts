// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Targets in Oracle Cloud Infrastructure Cloud Guard service.
 *
 * Returns a list of all Targets in a compartment
 * The ListTargets operation returns only the targets in `compartmentId` passed.
 * The list does not include any subcompartments of the compartmentId passed.
 *
 * The parameter `accessLevel` specifies whether to return only those compartments for which the
 * requestor has INSPECT permissions on at least one resource directly
 * or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
 * Principal doesn't have access to even one of the child compartments. This is valid only when
 * `compartmentIdInSubtree` is set to `true`.
 *
 * The parameter `compartmentIdInSubtree` applies when you perform ListTargets on the
 * `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
 * To get a full list of all compartments and subcompartments in the tenancy (root compartment),
 * set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTargets = oci.cloudguard.getTargets({
 *     compartmentId: _var.compartment_id,
 *     accessLevel: _var.target_access_level,
 *     compartmentIdInSubtree: _var.target_compartment_id_in_subtree,
 *     displayName: _var.target_display_name,
 *     state: _var.target_state,
 * });
 * ```
 */
export function getTargets(args: GetTargetsArgs, opts?: pulumi.InvokeOptions): Promise<GetTargetsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:cloudguard/getTargets:getTargets", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getTargets.
 */
export interface GetTargetsArgs {
    /**
     * Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
     */
    accessLevel?: string;
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
     */
    compartmentIdInSubtree?: boolean;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.cloudguard.GetTargetsFilter[];
    /**
     * The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     */
    state?: string;
}

/**
 * A collection of values returned by getTargets.
 */
export interface GetTargetsResult {
    readonly accessLevel?: string;
    /**
     * Compartment Identifier
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * ResponderRule Display Name
     */
    readonly displayName?: string;
    readonly filters?: outputs.cloudguard.GetTargetsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the ResponderRule.
     */
    readonly state?: string;
    /**
     * The list of target_collection.
     */
    readonly targetCollections: outputs.cloudguard.GetTargetsTargetCollection[];
}
