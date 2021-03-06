// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Db Node Console Connection resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets the specified database node console connection's information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbNodeConsoleConnection = oci.database.getDbNodeConsoleConnection({
 *     dbNodeId: oci_database_db_node.test_db_node.id,
 *     id: _var.db_node_console_connection_id,
 * });
 * ```
 */
export function getDbNodeConsoleConnection(args: GetDbNodeConsoleConnectionArgs, opts?: pulumi.InvokeOptions): Promise<GetDbNodeConsoleConnectionResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:database/getDbNodeConsoleConnection:getDbNodeConsoleConnection", {
        "dbNodeId": args.dbNodeId,
        "id": args.id,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbNodeConsoleConnection.
 */
export interface GetDbNodeConsoleConnectionArgs {
    /**
     * The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbNodeId: string;
    /**
     * The OCID of the console connection.
     */
    id: string;
}

/**
 * A collection of values returned by getDbNodeConsoleConnection.
 */
export interface GetDbNodeConsoleConnectionResult {
    /**
     * The OCID of the compartment to contain the console connection.
     */
    readonly compartmentId: string;
    /**
     * The SSH connection string for the console connection.
     */
    readonly connectionString: string;
    /**
     * The OCID of the database node.
     */
    readonly dbNodeId: string;
    /**
     * The SSH public key fingerprint for the console connection.
     */
    readonly fingerprint: string;
    /**
     * The OCID of the console connection.
     */
    readonly id: string;
    readonly publicKey: string;
    /**
     * The current state of the console connection.
     */
    readonly state: string;
}
