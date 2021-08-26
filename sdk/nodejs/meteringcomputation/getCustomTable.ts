// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Custom Table resource in Oracle Cloud Infrastructure Metering Computation service.
 *
 * Returns the saved custom table.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCustomTable = oci.meteringcomputation.getCustomTable({
 *     customTableId: oci_metering_computation_custom_table.test_custom_table.id,
 * });
 * ```
 */
export function getCustomTable(args: GetCustomTableArgs, opts?: pulumi.InvokeOptions): Promise<GetCustomTableResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:meteringcomputation/getCustomTable:getCustomTable", {
        "customTableId": args.customTableId,
    }, opts);
}

/**
 * A collection of arguments for invoking getCustomTable.
 */
export interface GetCustomTableArgs {
    /**
     * The custom table unique OCID.
     */
    customTableId: string;
}

/**
 * A collection of values returned by getCustomTable.
 */
export interface GetCustomTableResult {
    /**
     * The custom table compartment OCID.
     */
    readonly compartmentId: string;
    readonly customTableId: string;
    /**
     * The custom table OCID.
     */
    readonly id: string;
    /**
     * The custom table for Cost Analysis UI rendering.
     */
    readonly savedCustomTable: outputs.meteringcomputation.GetCustomTableSavedCustomTable;
    /**
     * The custom table associated saved report OCID.
     */
    readonly savedReportId: string;
}
