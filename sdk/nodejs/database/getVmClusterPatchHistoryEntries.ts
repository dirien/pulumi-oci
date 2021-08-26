// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Vm Cluster Patch History Entries in Oracle Cloud Infrastructure Database service.
 *
 * Gets the history of the patch actions performed on the specified VM cluster in an Exadata Cloud@Customer system.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVmClusterPatchHistoryEntries = oci.database.getVmClusterPatchHistoryEntries({
 *     vmClusterId: oci_database_vm_cluster.test_vm_cluster.id,
 * });
 * ```
 */
export function getVmClusterPatchHistoryEntries(args: GetVmClusterPatchHistoryEntriesArgs, opts?: pulumi.InvokeOptions): Promise<GetVmClusterPatchHistoryEntriesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:database/getVmClusterPatchHistoryEntries:getVmClusterPatchHistoryEntries", {
        "filters": args.filters,
        "vmClusterId": args.vmClusterId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVmClusterPatchHistoryEntries.
 */
export interface GetVmClusterPatchHistoryEntriesArgs {
    filters?: inputs.database.GetVmClusterPatchHistoryEntriesFilter[];
    /**
     * The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    vmClusterId: string;
}

/**
 * A collection of values returned by getVmClusterPatchHistoryEntries.
 */
export interface GetVmClusterPatchHistoryEntriesResult {
    readonly filters?: outputs.database.GetVmClusterPatchHistoryEntriesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of patch_history_entries.
     */
    readonly patchHistoryEntries: outputs.database.GetVmClusterPatchHistoryEntriesPatchHistoryEntry[];
    readonly vmClusterId: string;
}
