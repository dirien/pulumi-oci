// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Profile resource in Oracle Cloud Infrastructure Optimizer service.
 *
 * Gets the specified profile's information. Uses the profile's OCID to determine which profile to retrieve.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testProfile = oci.optimizer.getProfile({
 *     profileId: oci_optimizer_profile.test_profile.id,
 * });
 * ```
 */
export function getProfile(args: GetProfileArgs, opts?: pulumi.InvokeOptions): Promise<GetProfileResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:optimizer/getProfile:getProfile", {
        "profileId": args.profileId,
    }, opts);
}

/**
 * A collection of arguments for invoking getProfile.
 */
export interface GetProfileArgs {
    /**
     * The unique OCID of the profile.
     */
    profileId: string;
}

/**
 * A collection of values returned by getProfile.
 */
export interface GetProfileResult {
    /**
     * The OCID of the tenancy. The tenancy is the root compartment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Text describing the profile. Avoid entering confidential information.
     */
    readonly description: string;
    /**
     * Simple key-value pair applied without any predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Exists for cross-compatibility only.  Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The unique OCID of the profile.
     */
    readonly id: string;
    /**
     * A list of configuration levels for each recommendation.
     */
    readonly levelsConfiguration: outputs.optimizer.GetProfileLevelsConfiguration;
    /**
     * The name assigned to the profile. Avoid entering confidential information.
     */
    readonly name: string;
    readonly profileId: string;
    /**
     * The profile's current state.
     */
    readonly state: string;
    /**
     * Optional. The target compartments supported by a profile override for a recommendation.
     */
    readonly targetCompartments: outputs.optimizer.GetProfileTargetCompartments;
    /**
     * Optional. The target tags supported by a profile override for a recommendation.
     */
    readonly targetTags: outputs.optimizer.GetProfileTargetTags;
    /**
     * The date and time the profile was created, in the format defined by RFC3339.
     */
    readonly timeCreated: string;
    /**
     * The date and time the profile was last updated, in the format defined by RFC3339.
     */
    readonly timeUpdated: string;
}
