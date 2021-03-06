// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of File Systems in Oracle Cloud Infrastructure File Storage service.
 *
 * Lists the file system resources in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFileSystems = oci.filestorage.getFileSystems({
 *     availabilityDomain: _var.file_system_availability_domain,
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.file_system_display_name,
 *     id: _var.file_system_id,
 *     parentFileSystemId: oci_file_storage_file_system.test_file_system.id,
 *     sourceSnapshotId: oci_file_storage_snapshot.test_snapshot.id,
 *     state: _var.file_system_state,
 * });
 * ```
 */
export function getFileSystems(args: GetFileSystemsArgs, opts?: pulumi.InvokeOptions): Promise<GetFileSystemsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:filestorage/getFileSystems:getFileSystems", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "parentFileSystemId": args.parentFileSystemId,
        "sourceSnapshotId": args.sourceSnapshotId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getFileSystems.
 */
export interface GetFileSystemsArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
     */
    displayName?: string;
    filters?: inputs.filestorage.GetFileSystemsFilter[];
    /**
     * Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
     */
    id?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system that contains the source snapshot of a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
     */
    parentFileSystemId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot used to create a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
     */
    sourceSnapshotId?: string;
    /**
     * Filter results by the specified lifecycle state. Must be a valid state for the resource type.
     */
    state?: string;
}

/**
 * A collection of values returned by getFileSystems.
 */
export interface GetFileSystemsResult {
    /**
     * The availability domain the file system is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
     */
    readonly availabilityDomain: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the file system.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My file system`
     */
    readonly displayName?: string;
    /**
     * The list of file_systems.
     */
    readonly fileSystems: outputs.filestorage.GetFileSystemsFileSystem[];
    readonly filters?: outputs.filestorage.GetFileSystemsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
     */
    readonly id?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system that contains the source snapshot of a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
     */
    readonly parentFileSystemId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source snapshot used to create a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
     */
    readonly sourceSnapshotId?: string;
    /**
     * The current state of the file system.
     */
    readonly state?: string;
}
