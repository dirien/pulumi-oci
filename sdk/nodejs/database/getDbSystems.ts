// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Db Systems in Oracle Cloud Infrastructure Database service.
 *
 * Lists the DB systems in the specified compartment. You can specify a `backupId` to list only the DB systems that support creating a database using this backup in this compartment.
 *
 * **Note:** Deprecated for Exadata Cloud Service systems. Use the [new resource model APIs](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/exaflexsystem.htm#exaflexsystem_topic-resource_model) instead.
 *
 * For Exadata Cloud Service instances, support for this API will end on May 15th, 2021. See [Switching an Exadata DB System to the New Resource Model and APIs](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/exaflexsystem_topic-resource_model_conversion.htm) for details on converting existing Exadata DB systems to the new resource model.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbSystems = oci.database.getDbSystems({
 *     compartmentId: _var.compartment_id,
 *     availabilityDomain: _var.db_system_availability_domain,
 *     backupId: oci_database_backup.test_backup.id,
 *     displayName: _var.db_system_display_name,
 *     state: _var.db_system_state,
 * });
 * ```
 */
export function getDbSystems(args: GetDbSystemsArgs, opts?: pulumi.InvokeOptions): Promise<GetDbSystemsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:database/getDbSystems:getDbSystems", {
        "availabilityDomain": args.availabilityDomain,
        "backupId": args.backupId,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbSystems.
 */
export interface GetDbSystemsArgs {
    /**
     * A filter to return only resources that match the given availability domain exactly.
     */
    availabilityDomain?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup. Specify a backupId to list only the DB systems or DB homes that support creating a database using this backup in this compartment.
     */
    backupId?: string;
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    filters?: inputs.database.GetDbSystemsFilter[];
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: string;
}

/**
 * A collection of values returned by getDbSystems.
 */
export interface GetDbSystemsResult {
    /**
     * The name of the availability domain that the DB system is located in.
     */
    readonly availabilityDomain?: string;
    readonly backupId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The list of db_systems.
     */
    readonly dbSystems: outputs.database.GetDbSystemsDbSystem[];
    /**
     * The user-friendly name for the DB system. The name does not have to be unique.
     */
    readonly displayName?: string;
    readonly filters?: outputs.database.GetDbSystemsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the DB system.
     */
    readonly state?: string;
}
