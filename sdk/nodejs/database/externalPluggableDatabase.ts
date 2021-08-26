// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the External Pluggable Database resource in Oracle Cloud Infrastructure Database service.
 *
 * Registers a new [ExternalPluggableDatabase](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails)
 * resource.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalPluggableDatabase = new oci.database.ExternalPluggableDatabase("testExternalPluggableDatabase", {
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.external_pluggable_database_display_name,
 *     externalContainerDatabaseId: oci_database_external_container_database.test_external_container_database.id,
 *     definedTags: _var.external_pluggable_database_defined_tags,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     sourceId: oci_database_source.test_source.id,
 * });
 * ```
 *
 * ## Import
 *
 * ExternalPluggableDatabases can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:database/externalPluggableDatabase:ExternalPluggableDatabase test_external_pluggable_database "id"
 * ```
 */
export class ExternalPluggableDatabase extends pulumi.CustomResource {
    /**
     * Get an existing ExternalPluggableDatabase resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ExternalPluggableDatabaseState, opts?: pulumi.CustomResourceOptions): ExternalPluggableDatabase {
        return new ExternalPluggableDatabase(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:database/externalPluggableDatabase:ExternalPluggableDatabase';

    /**
     * Returns true if the given object is an instance of ExternalPluggableDatabase.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ExternalPluggableDatabase {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ExternalPluggableDatabase.__pulumiType;
    }

    /**
     * The character set of the external database.
     */
    public /*out*/ readonly characterSet!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The Oracle Database configuration
     */
    public /*out*/ readonly databaseConfiguration!: pulumi.Output<string>;
    /**
     * The Oracle Database edition.
     */
    public /*out*/ readonly databaseEdition!: pulumi.Output<string>;
    /**
     * The configuration of the Database Management service.
     */
    public /*out*/ readonly databaseManagementConfig!: pulumi.Output<outputs.database.ExternalPluggableDatabaseDatabaseManagementConfig>;
    /**
     * The Oracle Database version.
     */
    public /*out*/ readonly databaseVersion!: pulumi.Output<string>;
    /**
     * The Oracle Database ID, which identifies an Oracle Database located outside of Oracle Cloud.
     */
    public /*out*/ readonly dbId!: pulumi.Output<string>;
    /**
     * The database packs licensed for the external Oracle Database.
     */
    public /*out*/ readonly dbPacks!: pulumi.Output<string>;
    /**
     * The `DB_UNIQUE_NAME` of the external database.
     */
    public /*out*/ readonly dbUniqueName!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The user-friendly name for the external database. The name does not have to be unique.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalContainerDatabaseDetails) that contains the specified [external pluggable database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails) resource.
     */
    public readonly externalContainerDatabaseId!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Additional information about the current lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The national character of the external database.
     */
    public /*out*/ readonly ncharacterSet!: pulumi.Output<string>;
    /**
     * The configuration of Operations Insights for the external database
     */
    public /*out*/ readonly operationsInsightsConfig!: pulumi.Output<outputs.database.ExternalPluggableDatabaseOperationsInsightsConfig>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the the non-container database that was converted to a pluggable database to create this resource.
     */
    public readonly sourceId!: pulumi.Output<string>;
    /**
     * The current state of the Oracle Cloud Infrastructure external database resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the database was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time zone of the external database. It is a time zone offset (a character type in the format '[+|-]TZH:TZM') or a time zone region name, depending on how the time zone value was specified when the database was created / last altered.
     */
    public /*out*/ readonly timeZone!: pulumi.Output<string>;

    /**
     * Create a ExternalPluggableDatabase resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ExternalPluggableDatabaseArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ExternalPluggableDatabaseArgs | ExternalPluggableDatabaseState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ExternalPluggableDatabaseState | undefined;
            inputs["characterSet"] = state ? state.characterSet : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["databaseConfiguration"] = state ? state.databaseConfiguration : undefined;
            inputs["databaseEdition"] = state ? state.databaseEdition : undefined;
            inputs["databaseManagementConfig"] = state ? state.databaseManagementConfig : undefined;
            inputs["databaseVersion"] = state ? state.databaseVersion : undefined;
            inputs["dbId"] = state ? state.dbId : undefined;
            inputs["dbPacks"] = state ? state.dbPacks : undefined;
            inputs["dbUniqueName"] = state ? state.dbUniqueName : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["externalContainerDatabaseId"] = state ? state.externalContainerDatabaseId : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["ncharacterSet"] = state ? state.ncharacterSet : undefined;
            inputs["operationsInsightsConfig"] = state ? state.operationsInsightsConfig : undefined;
            inputs["sourceId"] = state ? state.sourceId : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeZone"] = state ? state.timeZone : undefined;
        } else {
            const args = argsOrState as ExternalPluggableDatabaseArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.externalContainerDatabaseId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'externalContainerDatabaseId'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["externalContainerDatabaseId"] = args ? args.externalContainerDatabaseId : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["sourceId"] = args ? args.sourceId : undefined;
            inputs["characterSet"] = undefined /*out*/;
            inputs["databaseConfiguration"] = undefined /*out*/;
            inputs["databaseEdition"] = undefined /*out*/;
            inputs["databaseManagementConfig"] = undefined /*out*/;
            inputs["databaseVersion"] = undefined /*out*/;
            inputs["dbId"] = undefined /*out*/;
            inputs["dbPacks"] = undefined /*out*/;
            inputs["dbUniqueName"] = undefined /*out*/;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["ncharacterSet"] = undefined /*out*/;
            inputs["operationsInsightsConfig"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeZone"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(ExternalPluggableDatabase.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ExternalPluggableDatabase resources.
 */
export interface ExternalPluggableDatabaseState {
    /**
     * The character set of the external database.
     */
    characterSet?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The Oracle Database configuration
     */
    databaseConfiguration?: pulumi.Input<string>;
    /**
     * The Oracle Database edition.
     */
    databaseEdition?: pulumi.Input<string>;
    /**
     * The configuration of the Database Management service.
     */
    databaseManagementConfig?: pulumi.Input<inputs.database.ExternalPluggableDatabaseDatabaseManagementConfig>;
    /**
     * The Oracle Database version.
     */
    databaseVersion?: pulumi.Input<string>;
    /**
     * The Oracle Database ID, which identifies an Oracle Database located outside of Oracle Cloud.
     */
    dbId?: pulumi.Input<string>;
    /**
     * The database packs licensed for the external Oracle Database.
     */
    dbPacks?: pulumi.Input<string>;
    /**
     * The `DB_UNIQUE_NAME` of the external database.
     */
    dbUniqueName?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The user-friendly name for the external database. The name does not have to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalContainerDatabaseDetails) that contains the specified [external pluggable database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails) resource.
     */
    externalContainerDatabaseId?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Additional information about the current lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The national character of the external database.
     */
    ncharacterSet?: pulumi.Input<string>;
    /**
     * The configuration of Operations Insights for the external database
     */
    operationsInsightsConfig?: pulumi.Input<inputs.database.ExternalPluggableDatabaseOperationsInsightsConfig>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the the non-container database that was converted to a pluggable database to create this resource.
     */
    sourceId?: pulumi.Input<string>;
    /**
     * The current state of the Oracle Cloud Infrastructure external database resource.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the database was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time zone of the external database. It is a time zone offset (a character type in the format '[+|-]TZH:TZM') or a time zone region name, depending on how the time zone value was specified when the database was created / last altered.
     */
    timeZone?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ExternalPluggableDatabase resource.
 */
export interface ExternalPluggableDatabaseArgs {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The user-friendly name for the external database. The name does not have to be unique.
     */
    displayName: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalContainerDatabaseDetails) that contains the specified [external pluggable database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails) resource.
     */
    externalContainerDatabaseId: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the the non-container database that was converted to a pluggable database to create this resource.
     */
    sourceId?: pulumi.Input<string>;
}
