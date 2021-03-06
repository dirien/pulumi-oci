// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Connections in Oracle Cloud Infrastructure Database Migration service.
 *
 * List all Database Connections.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testConnections = oci.databasemigration.getConnections({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.connection_display_name,
 *     state: _var.connection_state,
 * });
 * ```
 */
export function getConnections(args: GetConnectionsArgs, opts?: pulumi.InvokeOptions): Promise<GetConnectionsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:databasemigration/getConnections:getConnections", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getConnections.
 */
export interface GetConnectionsArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.databasemigration.GetConnectionsFilter[];
    /**
     * The current state of the Database Migration Deployment.
     */
    state?: string;
}

/**
 * A collection of values returned by getConnections.
 */
export interface GetConnectionsResult {
    /**
     * OCID of the compartment where the secret containing the credentials will be created.
     */
    readonly compartmentId: string;
    /**
     * The list of connection_collection.
     */
    readonly connectionCollections: outputs.databasemigration.GetConnectionsConnectionCollection[];
    /**
     * Database Connection display name identifier.
     */
    readonly displayName?: string;
    readonly filters?: outputs.databasemigration.GetConnectionsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the Connection resource.
     */
    readonly state?: string;
}
