// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Blockchain Platforms in Oracle Cloud Infrastructure Blockchain service.
 *
 * Returns a list Blockchain Platform Instances in a compartment
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBlockchainPlatforms = oci.blockchain.getBlockchainPlatforms({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.blockchain_platform_display_name,
 *     state: _var.blockchain_platform_state,
 * });
 * ```
 */
export function getBlockchainPlatforms(args: GetBlockchainPlatformsArgs, opts?: pulumi.InvokeOptions): Promise<GetBlockchainPlatformsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:blockchain/getBlockchainPlatforms:getBlockchainPlatforms", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getBlockchainPlatforms.
 */
export interface GetBlockchainPlatformsArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Example: `My new resource`
     */
    displayName?: string;
    filters?: inputs.blockchain.GetBlockchainPlatformsFilter[];
    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: string;
}

/**
 * A collection of values returned by getBlockchainPlatforms.
 */
export interface GetBlockchainPlatformsResult {
    /**
     * The list of blockchain_platform_collection.
     */
    readonly blockchainPlatformCollections: outputs.blockchain.GetBlockchainPlatformsBlockchainPlatformCollection[];
    /**
     * Compartment Identifier
     */
    readonly compartmentId: string;
    /**
     * Platform Instance Display name, can be renamed
     */
    readonly displayName?: string;
    readonly filters?: outputs.blockchain.GetBlockchainPlatformsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the Platform Instance.
     */
    readonly state?: string;
}
