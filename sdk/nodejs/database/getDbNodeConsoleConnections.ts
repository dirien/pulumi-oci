// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Db Node Console Connections in Oracle Cloud Infrastructure Database service.
 *
 * Lists the console connections for the specified database node.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbNodeConsoleConnections = oci.database.getDbNodeConsoleConnections({
 *     dbNodeId: oci_database_db_node.test_db_node.id,
 * });
 * ```
 */
export function getDbNodeConsoleConnections(args: GetDbNodeConsoleConnectionsArgs, opts?: pulumi.InvokeOptions): Promise<GetDbNodeConsoleConnectionsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:database/getDbNodeConsoleConnections:getDbNodeConsoleConnections", {
        "dbNodeId": args.dbNodeId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbNodeConsoleConnections.
 */
export interface GetDbNodeConsoleConnectionsArgs {
    /**
     * The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbNodeId: string;
    filters?: inputs.database.GetDbNodeConsoleConnectionsFilter[];
}

/**
 * A collection of values returned by getDbNodeConsoleConnections.
 */
export interface GetDbNodeConsoleConnectionsResult {
    /**
     * The list of console_connections.
     */
    readonly consoleConnections: outputs.database.GetDbNodeConsoleConnectionsConsoleConnection[];
    /**
     * The OCID of the database node.
     */
    readonly dbNodeId: string;
    readonly filters?: outputs.database.GetDbNodeConsoleConnectionsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
