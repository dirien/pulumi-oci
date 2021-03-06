// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Migration resource in Oracle Cloud Infrastructure Database Migration service.
 *
 * Create a Migration resource that contains all the details to perform the
 * database migration operation like source and destination database
 * details, credentials, etc.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMigration = new oci.databasemigration.Migration("testMigration", {
 *     compartmentId: _var.compartment_id,
 *     sourceDatabaseConnectionId: oci_database_migration_connection.test_connection.id,
 *     targetDatabaseConnectionId: oci_database_migration_connection.test_connection.id,
 *     type: _var.migration_type,
 *     agentId: oci_database_migration_agent.test_agent.id,
 *     dataTransferMediumDetails: {
 *         databaseLinkDetails: {
 *             name: _var.migration_data_transfer_medium_details_database_link_details_name,
 *         },
 *         objectStorageDetails: {
 *             bucket: _var.migration_data_transfer_medium_details_object_storage_details_bucket,
 *             namespace: _var.migration_data_transfer_medium_details_object_storage_details_namespace,
 *         },
 *     },
 *     datapumpSettings: {
 *         dataPumpParameters: {
 *             estimate: _var.migration_datapump_settings_data_pump_parameters_estimate,
 *             excludeParameters: _var.migration_datapump_settings_data_pump_parameters_exclude_parameters,
 *             exportParallelismDegree: _var.migration_datapump_settings_data_pump_parameters_export_parallelism_degree,
 *             importParallelismDegree: _var.migration_datapump_settings_data_pump_parameters_import_parallelism_degree,
 *             isCluster: _var.migration_datapump_settings_data_pump_parameters_is_cluster,
 *             tableExistsAction: _var.migration_datapump_settings_data_pump_parameters_table_exists_action,
 *         },
 *         exportDirectoryObject: {
 *             name: _var.migration_datapump_settings_export_directory_object_name,
 *             path: _var.migration_datapump_settings_export_directory_object_path,
 *         },
 *         importDirectoryObject: {
 *             name: _var.migration_datapump_settings_import_directory_object_name,
 *             path: _var.migration_datapump_settings_import_directory_object_path,
 *         },
 *         jobMode: _var.migration_datapump_settings_job_mode,
 *         metadataRemaps: [{
 *             newValue: _var.migration_datapump_settings_metadata_remaps_new_value,
 *             oldValue: _var.migration_datapump_settings_metadata_remaps_old_value,
 *             type: _var.migration_datapump_settings_metadata_remaps_type,
 *         }],
 *     },
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     displayName: _var.migration_display_name,
 *     excludeObjects: [{
 *         object: _var.migration_exclude_objects_object,
 *         owner: _var.migration_exclude_objects_owner,
 *     }],
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     goldenGateDetails: {
 *         hub: {
 *             restAdminCredentials: {
 *                 password: _var.migration_golden_gate_details_hub_rest_admin_credentials_password,
 *                 username: _var.migration_golden_gate_details_hub_rest_admin_credentials_username,
 *             },
 *             sourceDbAdminCredentials: {
 *                 password: _var.migration_golden_gate_details_hub_source_db_admin_credentials_password,
 *                 username: _var.migration_golden_gate_details_hub_source_db_admin_credentials_username,
 *             },
 *             sourceMicroservicesDeploymentName: oci_apigateway_deployment.test_deployment.name,
 *             targetDbAdminCredentials: {
 *                 password: _var.migration_golden_gate_details_hub_target_db_admin_credentials_password,
 *                 username: _var.migration_golden_gate_details_hub_target_db_admin_credentials_username,
 *             },
 *             targetMicroservicesDeploymentName: oci_apigateway_deployment.test_deployment.name,
 *             url: _var.migration_golden_gate_details_hub_url,
 *             computeId: oci_database_migration_compute.test_compute.id,
 *             sourceContainerDbAdminCredentials: {
 *                 password: _var.migration_golden_gate_details_hub_source_container_db_admin_credentials_password,
 *                 username: _var.migration_golden_gate_details_hub_source_container_db_admin_credentials_username,
 *             },
 *         },
 *         settings: {
 *             acceptableLag: _var.migration_golden_gate_details_settings_acceptable_lag,
 *             extract: {
 *                 longTransDuration: _var.migration_golden_gate_details_settings_extract_long_trans_duration,
 *                 performanceProfile: _var.migration_golden_gate_details_settings_extract_performance_profile,
 *             },
 *             replicat: {
 *                 mapParallelism: _var.migration_golden_gate_details_settings_replicat_map_parallelism,
 *                 maxApplyParallelism: _var.migration_golden_gate_details_settings_replicat_max_apply_parallelism,
 *                 minApplyParallelism: _var.migration_golden_gate_details_settings_replicat_min_apply_parallelism,
 *             },
 *         },
 *     },
 *     sourceContainerDatabaseConnectionId: oci_database_migration_connection.test_connection.id,
 *     vaultDetails: {
 *         compartmentId: _var.compartment_id,
 *         keyId: oci_kms_key.test_key.id,
 *         vaultId: oci_kms_vault.test_vault.id,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * Migrations can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:databasemigration/migration:Migration test_migration "id"
 * ```
 */
export class Migration extends pulumi.CustomResource {
    /**
     * Get an existing Migration resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MigrationState, opts?: pulumi.CustomResourceOptions): Migration {
        return new Migration(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:databasemigration/migration:Migration';

    /**
     * Returns true if the given object is an instance of Migration.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Migration {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Migration.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the registered ODMS Agent. Required for OFFLINE Migrations.
     */
    public readonly agentId!: pulumi.Output<string>;
    /**
     * (Updatable) OCID of the compartment where the secret containing the credentials will be created.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Migration credentials. Used to store Golden Gate admin user credentials.
     */
    public /*out*/ readonly credentialsSecretId!: pulumi.Output<string>;
    /**
     * (Updatable) Data Transfer Medium details for the Migration. If not specified, it will default to Database Link. Only one type of medium details can be specified.
     */
    public readonly dataTransferMediumDetails!: pulumi.Output<outputs.databasemigration.MigrationDataTransferMediumDetails>;
    /**
     * (Updatable) Optional settings for Datapump Export and Import jobs
     */
    public readonly datapumpSettings!: pulumi.Output<outputs.databasemigration.MigrationDatapumpSettings>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Migration Display Name
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Database objects to exclude from migration.
     */
    public readonly excludeObjects!: pulumi.Output<outputs.databasemigration.MigrationExcludeObject[]>;
    /**
     * OCID of the current ODMS Job in execution for the Migration, if any.
     */
    public /*out*/ readonly executingJobId!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
     */
    public readonly goldenGateDetails!: pulumi.Output<outputs.databasemigration.MigrationGoldenGateDetails>;
    /**
     * Additional status related to the execution and current state of the Migration.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the Source Container Database Connection. Only used for ONLINE migrations. Only Connections of type Non-Autonomous can be used as source container databases.
     */
    public readonly sourceContainerDatabaseConnectionId!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the Source Database Connection.
     */
    public readonly sourceDatabaseConnectionId!: pulumi.Output<string>;
    /**
     * The current state of the Migration Resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The OCID of the Target Database Connection.
     */
    public readonly targetDatabaseConnectionId!: pulumi.Output<string>;
    /**
     * The time the Migration was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time of last Migration. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeLastMigration!: pulumi.Output<string>;
    /**
     * The time of the last Migration details update. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * (Updatable) Migration type.
     */
    public readonly type!: pulumi.Output<string>;
    /**
     * (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
     */
    public readonly vaultDetails!: pulumi.Output<outputs.databasemigration.MigrationVaultDetails>;
    /**
     * Name of a migration phase. The Job will wait after executing this phase until the Resume Job endpoint is called.
     */
    public /*out*/ readonly waitAfter!: pulumi.Output<string>;

    /**
     * Create a Migration resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MigrationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MigrationArgs | MigrationState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MigrationState | undefined;
            inputs["agentId"] = state ? state.agentId : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["credentialsSecretId"] = state ? state.credentialsSecretId : undefined;
            inputs["dataTransferMediumDetails"] = state ? state.dataTransferMediumDetails : undefined;
            inputs["datapumpSettings"] = state ? state.datapumpSettings : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["excludeObjects"] = state ? state.excludeObjects : undefined;
            inputs["executingJobId"] = state ? state.executingJobId : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["goldenGateDetails"] = state ? state.goldenGateDetails : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["sourceContainerDatabaseConnectionId"] = state ? state.sourceContainerDatabaseConnectionId : undefined;
            inputs["sourceDatabaseConnectionId"] = state ? state.sourceDatabaseConnectionId : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["systemTags"] = state ? state.systemTags : undefined;
            inputs["targetDatabaseConnectionId"] = state ? state.targetDatabaseConnectionId : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeLastMigration"] = state ? state.timeLastMigration : undefined;
            inputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            inputs["type"] = state ? state.type : undefined;
            inputs["vaultDetails"] = state ? state.vaultDetails : undefined;
            inputs["waitAfter"] = state ? state.waitAfter : undefined;
        } else {
            const args = argsOrState as MigrationArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.sourceDatabaseConnectionId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'sourceDatabaseConnectionId'");
            }
            if ((!args || args.targetDatabaseConnectionId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'targetDatabaseConnectionId'");
            }
            if ((!args || args.type === undefined) && !opts.urn) {
                throw new Error("Missing required property 'type'");
            }
            inputs["agentId"] = args ? args.agentId : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["dataTransferMediumDetails"] = args ? args.dataTransferMediumDetails : undefined;
            inputs["datapumpSettings"] = args ? args.datapumpSettings : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["excludeObjects"] = args ? args.excludeObjects : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["goldenGateDetails"] = args ? args.goldenGateDetails : undefined;
            inputs["sourceContainerDatabaseConnectionId"] = args ? args.sourceContainerDatabaseConnectionId : undefined;
            inputs["sourceDatabaseConnectionId"] = args ? args.sourceDatabaseConnectionId : undefined;
            inputs["targetDatabaseConnectionId"] = args ? args.targetDatabaseConnectionId : undefined;
            inputs["type"] = args ? args.type : undefined;
            inputs["vaultDetails"] = args ? args.vaultDetails : undefined;
            inputs["credentialsSecretId"] = undefined /*out*/;
            inputs["executingJobId"] = undefined /*out*/;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["systemTags"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeLastMigration"] = undefined /*out*/;
            inputs["timeUpdated"] = undefined /*out*/;
            inputs["waitAfter"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(Migration.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Migration resources.
 */
export interface MigrationState {
    /**
     * (Updatable) The OCID of the registered ODMS Agent. Required for OFFLINE Migrations.
     */
    agentId?: pulumi.Input<string>;
    /**
     * (Updatable) OCID of the compartment where the secret containing the credentials will be created.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Migration credentials. Used to store Golden Gate admin user credentials.
     */
    credentialsSecretId?: pulumi.Input<string>;
    /**
     * (Updatable) Data Transfer Medium details for the Migration. If not specified, it will default to Database Link. Only one type of medium details can be specified.
     */
    dataTransferMediumDetails?: pulumi.Input<inputs.databasemigration.MigrationDataTransferMediumDetails>;
    /**
     * (Updatable) Optional settings for Datapump Export and Import jobs
     */
    datapumpSettings?: pulumi.Input<inputs.databasemigration.MigrationDatapumpSettings>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Migration Display Name
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Database objects to exclude from migration.
     */
    excludeObjects?: pulumi.Input<pulumi.Input<inputs.databasemigration.MigrationExcludeObject>[]>;
    /**
     * OCID of the current ODMS Job in execution for the Migration, if any.
     */
    executingJobId?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
     */
    goldenGateDetails?: pulumi.Input<inputs.databasemigration.MigrationGoldenGateDetails>;
    /**
     * Additional status related to the execution and current state of the Migration.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the Source Container Database Connection. Only used for ONLINE migrations. Only Connections of type Non-Autonomous can be used as source container databases.
     */
    sourceContainerDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the Source Database Connection.
     */
    sourceDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * The current state of the Migration Resource.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The OCID of the Target Database Connection.
     */
    targetDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * The time the Migration was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time of last Migration. An RFC3339 formatted datetime string.
     */
    timeLastMigration?: pulumi.Input<string>;
    /**
     * The time of the last Migration details update. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * (Updatable) Migration type.
     */
    type?: pulumi.Input<string>;
    /**
     * (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
     */
    vaultDetails?: pulumi.Input<inputs.databasemigration.MigrationVaultDetails>;
    /**
     * Name of a migration phase. The Job will wait after executing this phase until the Resume Job endpoint is called.
     */
    waitAfter?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Migration resource.
 */
export interface MigrationArgs {
    /**
     * (Updatable) The OCID of the registered ODMS Agent. Required for OFFLINE Migrations.
     */
    agentId?: pulumi.Input<string>;
    /**
     * (Updatable) OCID of the compartment where the secret containing the credentials will be created.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Data Transfer Medium details for the Migration. If not specified, it will default to Database Link. Only one type of medium details can be specified.
     */
    dataTransferMediumDetails?: pulumi.Input<inputs.databasemigration.MigrationDataTransferMediumDetails>;
    /**
     * (Updatable) Optional settings for Datapump Export and Import jobs
     */
    datapumpSettings?: pulumi.Input<inputs.databasemigration.MigrationDatapumpSettings>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Migration Display Name
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Database objects to exclude from migration.
     */
    excludeObjects?: pulumi.Input<pulumi.Input<inputs.databasemigration.MigrationExcludeObject>[]>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
     */
    goldenGateDetails?: pulumi.Input<inputs.databasemigration.MigrationGoldenGateDetails>;
    /**
     * (Updatable) The OCID of the Source Container Database Connection. Only used for ONLINE migrations. Only Connections of type Non-Autonomous can be used as source container databases.
     */
    sourceContainerDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the Source Database Connection.
     */
    sourceDatabaseConnectionId: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the Target Database Connection.
     */
    targetDatabaseConnectionId: pulumi.Input<string>;
    /**
     * (Updatable) Migration type.
     */
    type: pulumi.Input<string>;
    /**
     * (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
     */
    vaultDetails?: pulumi.Input<inputs.databasemigration.MigrationVaultDetails>;
}
