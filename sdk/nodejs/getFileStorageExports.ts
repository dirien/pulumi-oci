// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "./types";
import * as utilities from "./utilities";

/**
 * This data source provides the list of Exports in Oracle Cloud Infrastructure File Storage service.
 *
 * Lists export resources by compartment, file system, or export
 * set. You must specify an export set ID, a file system ID, and
 * / or a compartment ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExports = oci.GetFileStorageExports({
 *     compartmentId: _var.compartment_id,
 *     exportSetId: oci_file_storage_export_set.test_export_set.id,
 *     fileSystemId: oci_file_storage_file_system.test_file_system.id,
 *     id: _var.export_id,
 *     state: _var.export_state,
 * });
 * ```
 */
export function getFileStorageExports(args?: GetFileStorageExportsArgs, opts?: pulumi.InvokeOptions): Promise<GetFileStorageExportsResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:index/getFileStorageExports:GetFileStorageExports", {
        "compartmentId": args.compartmentId,
        "exportSetId": args.exportSetId,
        "fileSystemId": args.fileSystemId,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking GetFileStorageExports.
 */
export interface GetFileStorageExportsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export set.
     */
    exportSetId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
     */
    fileSystemId?: string;
    filters?: inputs.GetFileStorageExportsFilter[];
    /**
     * Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
     */
    id?: string;
    /**
     * Filter results by the specified lifecycle state. Must be a valid state for the resource type.
     */
    state?: string;
}

/**
 * A collection of values returned by GetFileStorageExports.
 */
export interface GetFileStorageExportsResult {
    readonly compartmentId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
     */
    readonly exportSetId?: string;
    /**
     * The list of exports.
     */
    readonly exports: outputs.GetFileStorageExportsExport[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
     */
    readonly fileSystemId?: string;
    readonly filters?: outputs.GetFileStorageExportsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export.
     */
    readonly id?: string;
    /**
     * The current state of this export.
     */
    readonly state?: string;
}