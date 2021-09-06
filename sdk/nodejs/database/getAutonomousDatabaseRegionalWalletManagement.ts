// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Autonomous Database Regional Wallet Management resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets the Autonomous Database regional wallet details.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousDatabaseRegionalWalletManagement = pulumi.output(oci.database.getAutonomousDatabaseRegionalWalletManagement());
 * ```
 */
export function getAutonomousDatabaseRegionalWalletManagement(opts?: pulumi.InvokeOptions): Promise<GetAutonomousDatabaseRegionalWalletManagementResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:database/getAutonomousDatabaseRegionalWalletManagement:getAutonomousDatabaseRegionalWalletManagement", {
    }, opts);
}

/**
 * A collection of values returned by getAutonomousDatabaseRegionalWalletManagement.
 */
export interface GetAutonomousDatabaseRegionalWalletManagementResult {
    readonly id: string;
    readonly shouldRotate: boolean;
    /**
     * The current lifecycle state of the Autonomous Database wallet.
     */
    readonly state: string;
    /**
     * The date and time the wallet was last rotated.
     */
    readonly timeRotated: string;
}
