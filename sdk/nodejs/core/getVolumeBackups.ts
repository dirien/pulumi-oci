// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Volume Backups in Oracle Cloud Infrastructure Core service.
 *
 * Lists the volume backups in the specified compartment. You can filter the results by volume.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVolumeBackups = oci.core.getVolumeBackups({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.volume_backup_display_name,
 *     sourceVolumeBackupId: oci_core_volume_backup.test_volume_backup.id,
 *     state: _var.volume_backup_state,
 *     volumeId: oci_core_volume.test_volume.id,
 * });
 * ```
 */
export function getVolumeBackups(args: GetVolumeBackupsArgs, opts?: pulumi.InvokeOptions): Promise<GetVolumeBackupsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:core/getVolumeBackups:getVolumeBackups", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "sourceVolumeBackupId": args.sourceVolumeBackupId,
        "state": args.state,
        "volumeId": args.volumeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVolumeBackups.
 */
export interface GetVolumeBackupsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.core.GetVolumeBackupsFilter[];
    /**
     * A filter to return only resources that originated from the given source volume backup.
     */
    sourceVolumeBackupId?: string;
    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: string;
    /**
     * The OCID of the volume.
     */
    volumeId?: string;
}

/**
 * A collection of values returned by getVolumeBackups.
 */
export interface GetVolumeBackupsResult {
    /**
     * The OCID of the compartment that contains the volume backup.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name for the volume backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.core.GetVolumeBackupsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The OCID of the source volume backup.
     */
    readonly sourceVolumeBackupId?: string;
    /**
     * The current state of a volume backup.
     */
    readonly state?: string;
    /**
     * The list of volume_backups.
     */
    readonly volumeBackups: outputs.core.GetVolumeBackupsVolumeBackup[];
    /**
     * The OCID of the volume.
     */
    readonly volumeId?: string;
}
