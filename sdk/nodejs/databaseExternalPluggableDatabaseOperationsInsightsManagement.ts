// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

/**
 * This resource provides the External Pluggable Database Operations Insights Management resource in Oracle Cloud Infrastructure Database service.
 *
 * Enable Operations Insights for the external pluggable database.
 * When deleting this resource block , we call disable if it was in enabled state .
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalPluggableDatabaseOperationsInsightsManagement = new oci.DatabaseExternalPluggableDatabaseOperationsInsightsManagement("testExternalPluggableDatabaseOperationsInsightsManagement", {
 *     externalDatabaseConnectorId: oci_database_external_database_connector.test_external_database_connector.id,
 *     externalPluggableDatabaseId: oci_database_external_pluggable_database.test_external_pluggable_database.id,
 *     enableOperationsInsights: true,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class DatabaseExternalPluggableDatabaseOperationsInsightsManagement extends pulumi.CustomResource {
    /**
     * Get an existing DatabaseExternalPluggableDatabaseOperationsInsightsManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DatabaseExternalPluggableDatabaseOperationsInsightsManagementState, opts?: pulumi.CustomResourceOptions): DatabaseExternalPluggableDatabaseOperationsInsightsManagement {
        return new DatabaseExternalPluggableDatabaseOperationsInsightsManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:index/databaseExternalPluggableDatabaseOperationsInsightsManagement:DatabaseExternalPluggableDatabaseOperationsInsightsManagement';

    /**
     * Returns true if the given object is an instance of DatabaseExternalPluggableDatabaseOperationsInsightsManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DatabaseExternalPluggableDatabaseOperationsInsightsManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DatabaseExternalPluggableDatabaseOperationsInsightsManagement.__pulumiType;
    }

    /**
     * (Updatable) Enabling OPSI on External Pluggable Databases . Requires boolean value "true" or "false".
     */
    public readonly enableOperationsInsights!: pulumi.Output<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     */
    public readonly externalDatabaseConnectorId!: pulumi.Output<string>;
    /**
     * The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    public readonly externalPluggableDatabaseId!: pulumi.Output<string>;

    /**
     * Create a DatabaseExternalPluggableDatabaseOperationsInsightsManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DatabaseExternalPluggableDatabaseOperationsInsightsManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DatabaseExternalPluggableDatabaseOperationsInsightsManagementArgs | DatabaseExternalPluggableDatabaseOperationsInsightsManagementState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DatabaseExternalPluggableDatabaseOperationsInsightsManagementState | undefined;
            inputs["enableOperationsInsights"] = state ? state.enableOperationsInsights : undefined;
            inputs["externalDatabaseConnectorId"] = state ? state.externalDatabaseConnectorId : undefined;
            inputs["externalPluggableDatabaseId"] = state ? state.externalPluggableDatabaseId : undefined;
        } else {
            const args = argsOrState as DatabaseExternalPluggableDatabaseOperationsInsightsManagementArgs | undefined;
            if ((!args || args.enableOperationsInsights === undefined) && !opts.urn) {
                throw new Error("Missing required property 'enableOperationsInsights'");
            }
            if ((!args || args.externalDatabaseConnectorId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'externalDatabaseConnectorId'");
            }
            if ((!args || args.externalPluggableDatabaseId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'externalPluggableDatabaseId'");
            }
            inputs["enableOperationsInsights"] = args ? args.enableOperationsInsights : undefined;
            inputs["externalDatabaseConnectorId"] = args ? args.externalDatabaseConnectorId : undefined;
            inputs["externalPluggableDatabaseId"] = args ? args.externalPluggableDatabaseId : undefined;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(DatabaseExternalPluggableDatabaseOperationsInsightsManagement.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DatabaseExternalPluggableDatabaseOperationsInsightsManagement resources.
 */
export interface DatabaseExternalPluggableDatabaseOperationsInsightsManagementState {
    /**
     * (Updatable) Enabling OPSI on External Pluggable Databases . Requires boolean value "true" or "false".
     */
    enableOperationsInsights?: pulumi.Input<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     */
    externalDatabaseConnectorId?: pulumi.Input<string>;
    /**
     * The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    externalPluggableDatabaseId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DatabaseExternalPluggableDatabaseOperationsInsightsManagement resource.
 */
export interface DatabaseExternalPluggableDatabaseOperationsInsightsManagementArgs {
    /**
     * (Updatable) Enabling OPSI on External Pluggable Databases . Requires boolean value "true" or "false".
     */
    enableOperationsInsights: pulumi.Input<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     */
    externalDatabaseConnectorId: pulumi.Input<string>;
    /**
     * The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    externalPluggableDatabaseId: pulumi.Input<string>;
}