// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Data Guard Associations in Oracle Cloud Infrastructure Database service.
 *
 * Lists all Data Guard associations for the specified database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataGuardAssociations = oci.database.getDataGuardAssociations({
 *     databaseId: oci_database_database.test_database.id,
 * });
 * ```
 */
export function getDataGuardAssociations(args: GetDataGuardAssociationsArgs, opts?: pulumi.InvokeOptions): Promise<GetDataGuardAssociationsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:database/getDataGuardAssociations:getDataGuardAssociations", {
        "databaseId": args.databaseId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getDataGuardAssociations.
 */
export interface GetDataGuardAssociationsArgs {
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    databaseId: string;
    filters?: inputs.database.GetDataGuardAssociationsFilter[];
}

/**
 * A collection of values returned by getDataGuardAssociations.
 */
export interface GetDataGuardAssociationsResult {
    /**
     * The list of data_guard_associations.
     */
    readonly dataGuardAssociations: outputs.database.GetDataGuardAssociationsDataGuardAssociation[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the reporting database.
     */
    readonly databaseId: string;
    readonly filters?: outputs.database.GetDataGuardAssociationsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
