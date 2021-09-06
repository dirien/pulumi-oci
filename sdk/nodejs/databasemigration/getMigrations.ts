// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Migrations in Oracle Cloud Infrastructure Database Migration service.
 *
 * List all Migrations.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMigrations = oci.databasemigration.getMigrations({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.migration_display_name,
 *     lifecycleDetails: _var.migration_lifecycle_details,
 *     state: _var.migration_state,
 * });
 * ```
 */
export function getMigrations(args: GetMigrationsArgs, opts?: pulumi.InvokeOptions): Promise<GetMigrationsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:databasemigration/getMigrations:getMigrations", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "lifecycleDetails": args.lifecycleDetails,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getMigrations.
 */
export interface GetMigrationsArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.databasemigration.GetMigrationsFilter[];
    /**
     * The lifecycle detailed status of the Migration.
     */
    lifecycleDetails?: string;
    /**
     * The current state of the Database Migration Deployment.
     */
    state?: string;
}

/**
 * A collection of values returned by getMigrations.
 */
export interface GetMigrationsResult {
    /**
     * OCID of the compartment where the secret containing the credentials will be created.
     */
    readonly compartmentId: string;
    /**
     * Migration Display Name
     */
    readonly displayName?: string;
    readonly filters?: outputs.databasemigration.GetMigrationsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Additional status related to the execution and current state of the Migration.
     */
    readonly lifecycleDetails?: string;
    /**
     * The list of migration_collection.
     */
    readonly migrationCollections: outputs.databasemigration.GetMigrationsMigrationCollection[];
    /**
     * The current state of the Migration Resource.
     */
    readonly state?: string;
}
