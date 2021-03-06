// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed Databases Database Parameters in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the list of database parameters for the specified Managed Database. The parameters are listed in alphabetical order, along with their current values.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabasesDatabaseParameters = oci.databasemanagement.getManagedDatabasesDatabaseParameters({
 *     managedDatabaseId: oci_database_management_managed_database.test_managed_database.id,
 *     isAllowedValuesIncluded: _var.managed_databases_database_parameter_is_allowed_values_included,
 *     name: _var.managed_databases_database_parameter_name,
 *     source: _var.managed_databases_database_parameter_source,
 * });
 * ```
 */
export function getManagedDatabasesDatabaseParameters(args: GetManagedDatabasesDatabaseParametersArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedDatabasesDatabaseParametersResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:databasemanagement/getManagedDatabasesDatabaseParameters:getManagedDatabasesDatabaseParameters", {
        "filters": args.filters,
        "isAllowedValuesIncluded": args.isAllowedValuesIncluded,
        "managedDatabaseId": args.managedDatabaseId,
        "name": args.name,
        "source": args.source,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabasesDatabaseParameters.
 */
export interface GetManagedDatabasesDatabaseParametersArgs {
    filters?: inputs.databasemanagement.GetManagedDatabasesDatabaseParametersFilter[];
    /**
     * When true, results include a list of valid values for parameters (if applicable).
     */
    isAllowedValuesIncluded?: boolean;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: string;
    /**
     * A filter to return all parameters that have the text given in their names.
     */
    name?: string;
    /**
     * The source used to list database parameters. `CURRENT` is used to get the database parameters that are currently in effect for the database instance. `SPFILE` is used to list parameters from the server parameter file. Default is `CURRENT`.
     */
    source?: string;
}

/**
 * A collection of values returned by getManagedDatabasesDatabaseParameters.
 */
export interface GetManagedDatabasesDatabaseParametersResult {
    /**
     * The list of database_parameters_collection.
     */
    readonly databaseParametersCollections: outputs.databasemanagement.GetManagedDatabasesDatabaseParametersDatabaseParametersCollection[];
    readonly filters?: outputs.databasemanagement.GetManagedDatabasesDatabaseParametersFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly isAllowedValuesIncluded?: boolean;
    readonly managedDatabaseId: string;
    /**
     * The parameter name.
     */
    readonly name?: string;
    readonly source?: string;
}
