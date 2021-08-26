// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Db Home resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified Database Home.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbHome = oci.database.getDbHome({
 *     dbHomeId: _var.db_home_id,
 * });
 * ```
 */
export function getDbHome(args: GetDbHomeArgs, opts?: pulumi.InvokeOptions): Promise<GetDbHomeResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:database/getDbHome:getDbHome", {
        "dbHomeId": args.dbHomeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbHome.
 */
export interface GetDbHomeArgs {
    /**
     * The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbHomeId: string;
}

/**
 * A collection of values returned by getDbHome.
 */
export interface GetDbHomeResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    readonly database: outputs.database.GetDbHomeDatabase;
    /**
     * The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     */
    readonly databaseSoftwareImageId: string;
    readonly dbHomeId: string;
    /**
     * The location of the Oracle Database Home.
     */
    readonly dbHomeLocation: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
     */
    readonly dbSystemId: string;
    /**
     * The Oracle Database version.
     */
    readonly dbVersion: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly definedTags: {[key: string]: any};
    /**
     * The user-provided name for the Database Home. The name does not need to be unique.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
     */
    readonly id: string;
    readonly isDesupportedVersion: boolean;
    /**
     * The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     */
    readonly kmsKeyId: string;
    readonly kmsKeyVersionId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation is started.
     */
    readonly lastPatchHistoryEntryId: string;
    /**
     * Additional information about the current lifecycle state.
     */
    readonly lifecycleDetails: string;
    readonly source: string;
    /**
     * The current state of the Database Home.
     */
    readonly state: string;
    /**
     * The date and time the Database Home was created.
     */
    readonly timeCreated: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
     */
    readonly vmClusterId: string;
}
