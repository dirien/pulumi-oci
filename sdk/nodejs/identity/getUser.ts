// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific User resource in Oracle Cloud Infrastructure Identity service.
 *
 * Gets the specified user's information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUser = oci.identity.getUser({
 *     userId: oci_identity_user.test_user.id,
 * });
 * ```
 */
export function getUser(args: GetUserArgs, opts?: pulumi.InvokeOptions): Promise<GetUserResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:identity/getUser:getUser", {
        "userId": args.userId,
    }, opts);
}

/**
 * A collection of arguments for invoking getUser.
 */
export interface GetUserArgs {
    /**
     * The OCID of the user.
     */
    userId: string;
}

/**
 * A collection of values returned by getUser.
 */
export interface GetUserResult {
    /**
     * Properties indicating how the user is allowed to authenticate.
     */
    readonly capabilities: outputs.identity.GetUserCapabilities;
    /**
     * The OCID of the tenancy containing the user.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * The description you assign to the user. Does not have to be unique, and it's changeable.
     */
    readonly description: string;
    /**
     * The email address you assign to the user. The email address must be unique across all users in the tenancy.
     */
    readonly email: string;
    /**
     * Whether the email address has been validated.
     */
    readonly emailVerified: boolean;
    /**
     * Identifier of the user in the identity provider
     */
    readonly externalIdentifier: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The OCID of the user.
     */
    readonly id: string;
    /**
     * The OCID of the `IdentityProvider` this user belongs to.
     */
    readonly identityProviderId: string;
    /**
     * Returned only if the user's `lifecycleState` is INACTIVE. A 16-bit value showing the reason why the user is inactive:
     * * bit 0: SUSPENDED (reserved for future use)
     * * bit 1: DISABLED (reserved for future use)
     * * bit 2: BLOCKED (the user has exceeded the maximum number of failed login attempts for the Console)
     */
    readonly inactiveState: string;
    /**
     * The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
     */
    readonly lastSuccessfulLoginTime: string;
    /**
     * The name you assign to the user during creation. This is the user's login for the Console. The name must be unique across all users in the tenancy and cannot be changed.
     */
    readonly name: string;
    /**
     * The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
     */
    readonly previousSuccessfulLoginTime: string;
    /**
     * The user's current state.
     */
    readonly state: string;
    /**
     * Date and time the user was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
    readonly userId: string;
}
