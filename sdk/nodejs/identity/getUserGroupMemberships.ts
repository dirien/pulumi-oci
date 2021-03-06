// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of User Group Memberships in Oracle Cloud Infrastructure Identity service.
 *
 * Lists the `UserGroupMembership` objects in your tenancy. You must specify your tenancy's OCID
 * as the value for the compartment ID
 * (see [Where to Get the Tenancy's OCID and User's OCID](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm#five)).
 * You must also then filter the list in one of these ways:
 *
 * - You can limit the results to just the memberships for a given user by specifying a `userId`.
 * - Similarly, you can limit the results to just the memberships for a given group by specifying a `groupId`.
 * - You can set both the `userId` and `groupId` to determine if the specified user is in the specified group.
 *   If the answer is no, the response is an empty list.
 * - Although`userId` and `groupId` are not individually required, you must set one of them.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUserGroupMemberships = oci.identity.getUserGroupMemberships({
 *     compartmentId: _var.tenancy_ocid,
 *     groupId: oci_identity_group.test_group.id,
 *     userId: oci_identity_user.test_user.id,
 * });
 * ```
 */
export function getUserGroupMemberships(args: GetUserGroupMembershipsArgs, opts?: pulumi.InvokeOptions): Promise<GetUserGroupMembershipsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:identity/getUserGroupMemberships:getUserGroupMemberships", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "groupId": args.groupId,
        "userId": args.userId,
    }, opts);
}

/**
 * A collection of arguments for invoking getUserGroupMemberships.
 */
export interface GetUserGroupMembershipsArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId: string;
    filters?: inputs.identity.GetUserGroupMembershipsFilter[];
    /**
     * The OCID of the group.
     */
    groupId?: string;
    /**
     * The OCID of the user.
     */
    userId?: string;
}

/**
 * A collection of values returned by getUserGroupMemberships.
 */
export interface GetUserGroupMembershipsResult {
    /**
     * The OCID of the tenancy containing the user, group, and membership object.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.identity.GetUserGroupMembershipsFilter[];
    /**
     * The OCID of the group.
     */
    readonly groupId?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of memberships.
     */
    readonly memberships: outputs.identity.GetUserGroupMembershipsMembership[];
    /**
     * The OCID of the user.
     */
    readonly userId?: string;
}
