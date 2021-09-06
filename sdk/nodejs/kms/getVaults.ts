// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Vaults in Oracle Cloud Infrastructure Kms service.
 *
 * Lists the vaults in the specified compartment.
 *
 * As a provisioning operation, this call is subject to a Key Management limit that applies to
 * the total number of requests across all provisioning read operations. Key Management might
 * throttle this call to reject an otherwise valid request when the total rate of provisioning
 * read operations exceeds 10 requests per second for a given tenancy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVaults = oci.kms.getVaults({
 *     compartmentId: _var.compartment_id,
 * });
 * ```
 */
export function getVaults(args: GetVaultsArgs, opts?: pulumi.InvokeOptions): Promise<GetVaultsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:kms/getVaults:getVaults", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getVaults.
 */
export interface GetVaultsArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: string;
    filters?: inputs.kms.GetVaultsFilter[];
}

/**
 * A collection of values returned by getVaults.
 */
export interface GetVaultsResult {
    /**
     * The OCID of the compartment that contains a particular vault.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.kms.GetVaultsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of vaults.
     */
    readonly vaults: outputs.kms.GetVaultsVault[];
}
