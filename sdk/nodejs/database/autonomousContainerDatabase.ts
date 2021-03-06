// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Autonomous Container Database resource in Oracle Cloud Infrastructure Database service.
 *
 * Creates an Autonomous Container Database in the specified Autonomous Exadata Infrastructure.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousContainerDatabase = new oci.database.AutonomousContainerDatabase("testAutonomousContainerDatabase", {
 *     displayName: _var.autonomous_container_database_display_name,
 *     patchModel: _var.autonomous_container_database_patch_model,
 *     autonomousExadataInfrastructureId: oci_database_autonomous_exadata_infrastructure.test_autonomous_exadata_infrastructure.id,
 *     autonomousVmClusterId: oci_database_autonomous_vm_cluster.test_autonomous_vm_cluster.id,
 *     backupConfig: {
 *         backupDestinationDetails: {
 *             type: _var.autonomous_container_database_backup_config_backup_destination_details_type,
 *             id: _var.autonomous_container_database_backup_config_backup_destination_details_id,
 *             internetProxy: _var.autonomous_container_database_backup_config_backup_destination_details_internet_proxy,
 *             vpcPassword: _var.autonomous_container_database_backup_config_backup_destination_details_vpc_password,
 *             vpcUser: _var.autonomous_container_database_backup_config_backup_destination_details_vpc_user,
 *         },
 *         recoveryWindowInDays: _var.autonomous_container_database_backup_config_recovery_window_in_days,
 *     },
 *     compartmentId: _var.compartment_id,
 *     dbUniqueName: _var.autonomous_container_database_db_unique_name,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     keyStoreId: oci_database_key_store.test_key_store.id,
 *     kmsKeyId: oci_kms_key.test_key.id,
 *     maintenanceWindowDetails: {
 *         preference: _var.autonomous_container_database_maintenance_window_details_preference,
 *         daysOfWeeks: [{
 *             name: _var.autonomous_container_database_maintenance_window_details_days_of_week_name,
 *         }],
 *         hoursOfDays: _var.autonomous_container_database_maintenance_window_details_hours_of_day,
 *         leadTimeInWeeks: _var.autonomous_container_database_maintenance_window_details_lead_time_in_weeks,
 *         months: [{
 *             name: _var.autonomous_container_database_maintenance_window_details_months_name,
 *         }],
 *         weeksOfMonths: _var.autonomous_container_database_maintenance_window_details_weeks_of_month,
 *     },
 *     peerAutonomousContainerDatabaseDisplayName: _var.autonomous_container_database_peer_autonomous_container_database_display_name,
 *     peerAutonomousExadataInfrastructureId: oci_database_autonomous_exadata_infrastructure.test_autonomous_exadata_infrastructure.id,
 *     protectionMode: _var.autonomous_container_database_protection_mode,
 *     peerAutonomousContainerDatabaseBackupConfig: {
 *         backupDestinationDetails: [{
 *             type: _var.autonomous_container_database_peer_autonomous_container_database_backup_config_backup_destination_details_type,
 *             id: _var.autonomous_container_database_peer_autonomous_container_database_backup_config_backup_destination_details_id,
 *             internetProxy: _var.autonomous_container_database_peer_autonomous_container_database_backup_config_backup_destination_details_internet_proxy,
 *             vpcPassword: _var.autonomous_container_database_peer_autonomous_container_database_backup_config_backup_destination_details_vpc_password,
 *             vpcUser: _var.autonomous_container_database_peer_autonomous_container_database_backup_config_backup_destination_details_vpc_user,
 *         }],
 *         recoveryWindowInDays: _var.autonomous_container_database_peer_autonomous_container_database_backup_config_recovery_window_in_days,
 *     },
 *     peerAutonomousContainerDatabaseCompartmentId: oci_identity_compartment.test_compartment.id,
 *     peerAutonomousVmClusterId: oci_database_autonomous_vm_cluster.test_autonomous_vm_cluster.id,
 *     peerDbUniqueName: _var.autonomous_container_database_peer_db_unique_name,
 *     serviceLevelAgreementType: _var.autonomous_container_database_service_level_agreement_type,
 *     vaultId: oci_kms_vault.test_vault.id,
 *     standbyMaintenanceBufferInDays: _var.autonomous_container_database_standby_maintenance_buffer_in_days,
 * });
 * ```
 *
 * ## Import
 *
 * AutonomousContainerDatabases can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:database/autonomousContainerDatabase:AutonomousContainerDatabase test_autonomous_container_database "id"
 * ```
 */
export class AutonomousContainerDatabase extends pulumi.CustomResource {
    /**
     * Get an existing AutonomousContainerDatabase resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AutonomousContainerDatabaseState, opts?: pulumi.CustomResourceOptions): AutonomousContainerDatabase {
        return new AutonomousContainerDatabase(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:database/autonomousContainerDatabase:AutonomousContainerDatabase';

    /**
     * Returns true if the given object is an instance of AutonomousContainerDatabase.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AutonomousContainerDatabase {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AutonomousContainerDatabase.__pulumiType;
    }

    /**
     * The OCID of the Autonomous Exadata Infrastructure.
     */
    public readonly autonomousExadataInfrastructureId!: pulumi.Output<string>;
    /**
     * The OCID of the Autonomous VM Cluster.
     */
    public readonly autonomousVmClusterId!: pulumi.Output<string>;
    /**
     * The availability domain of the Autonomous Container Database.
     */
    public /*out*/ readonly availabilityDomain!: pulumi.Output<string>;
    /**
     * (Updatable) Backup options for the Autonomous Container Database.
     */
    public readonly backupConfig!: pulumi.Output<outputs.database.AutonomousContainerDatabaseBackupConfig>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Autonomous Container Database.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The `DB_UNIQUE_NAME` of the Oracle Database being backed up.
     */
    public readonly dbUniqueName!: pulumi.Output<string>;
    /**
     * Oracle Database version of the Autonomous Container Database.
     */
    public /*out*/ readonly dbVersion!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The display name for the Autonomous Container Database.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The infrastructure type this resource belongs to.
     */
    public /*out*/ readonly infrastructureType!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     */
    public readonly keyStoreId!: pulumi.Output<string>;
    /**
     * The wallet name for Oracle Key Vault.
     */
    public /*out*/ readonly keyStoreWalletName!: pulumi.Output<string>;
    /**
     * The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     */
    public readonly kmsKeyId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     */
    public /*out*/ readonly lastMaintenanceRunId!: pulumi.Output<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     */
    public /*out*/ readonly maintenanceWindow!: pulumi.Output<outputs.database.AutonomousContainerDatabaseMaintenanceWindow>;
    /**
     * (Updatable) The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     */
    public readonly maintenanceWindowDetails!: pulumi.Output<outputs.database.AutonomousContainerDatabaseMaintenanceWindowDetails | undefined>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     */
    public /*out*/ readonly nextMaintenanceRunId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch applied on the system.
     */
    public /*out*/ readonly patchId!: pulumi.Output<string>;
    /**
     * (Updatable) Database Patch model preference.
     */
    public readonly patchModel!: pulumi.Output<string>;
    public readonly peerAutonomousContainerDatabaseBackupConfig!: pulumi.Output<outputs.database.AutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the standby Autonomous Container Database will be created.
     */
    public readonly peerAutonomousContainerDatabaseCompartmentId!: pulumi.Output<string>;
    /**
     * The display name for the peer Autonomous Container Database.
     */
    public readonly peerAutonomousContainerDatabaseDisplayName!: pulumi.Output<string>;
    /**
     * The OCID of the peer Autonomous Exadata Infrastructure for autonomous dataguard.
     */
    public readonly peerAutonomousExadataInfrastructureId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous VM cluster for Autonomous Data Guard. Required to enable Data Guard.
     */
    public readonly peerAutonomousVmClusterId!: pulumi.Output<string>;
    /**
     * The `DB_UNIQUE_NAME` of the peer Autonomous Container Database in a Data Guard association.
     */
    public readonly peerDbUniqueName!: pulumi.Output<string>;
    /**
     * The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     */
    public readonly protectionMode!: pulumi.Output<string>;
    /**
     * The role of the dataguard enabled Autonomous Container Database.
     */
    public /*out*/ readonly role!: pulumi.Output<string>;
    /**
     * (Updatable) An optional property when flipped triggers rotation of KMS key. It is only applicable on dedicated container databases i.e. where `autonomousExadataInfrastructureId` is set.
     */
    public readonly rotateKeyTrigger!: pulumi.Output<boolean | undefined>;
    /**
     * The service level agreement type of the Autonomous Container Database. The default is STANDARD. For an autonomous dataguard Autonomous Container Database, the specified Autonomous Exadata Infrastructure must be associated with a remote Autonomous Exadata Infrastructure.
     */
    public readonly serviceLevelAgreementType!: pulumi.Output<string>;
    /**
     * (Updatable) The scheduling detail for the quarterly maintenance window of standby Autonomous Container Database. This value represents the number of days before the primary database maintenance schedule.
     */
    public readonly standbyMaintenanceBufferInDays!: pulumi.Output<number>;
    /**
     * The current state of the Autonomous Container Database.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the Autonomous Container Database was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     */
    public readonly vaultId!: pulumi.Output<string>;

    /**
     * Create a AutonomousContainerDatabase resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AutonomousContainerDatabaseArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AutonomousContainerDatabaseArgs | AutonomousContainerDatabaseState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AutonomousContainerDatabaseState | undefined;
            inputs["autonomousExadataInfrastructureId"] = state ? state.autonomousExadataInfrastructureId : undefined;
            inputs["autonomousVmClusterId"] = state ? state.autonomousVmClusterId : undefined;
            inputs["availabilityDomain"] = state ? state.availabilityDomain : undefined;
            inputs["backupConfig"] = state ? state.backupConfig : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["dbUniqueName"] = state ? state.dbUniqueName : undefined;
            inputs["dbVersion"] = state ? state.dbVersion : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["infrastructureType"] = state ? state.infrastructureType : undefined;
            inputs["keyStoreId"] = state ? state.keyStoreId : undefined;
            inputs["keyStoreWalletName"] = state ? state.keyStoreWalletName : undefined;
            inputs["kmsKeyId"] = state ? state.kmsKeyId : undefined;
            inputs["lastMaintenanceRunId"] = state ? state.lastMaintenanceRunId : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["maintenanceWindow"] = state ? state.maintenanceWindow : undefined;
            inputs["maintenanceWindowDetails"] = state ? state.maintenanceWindowDetails : undefined;
            inputs["nextMaintenanceRunId"] = state ? state.nextMaintenanceRunId : undefined;
            inputs["patchId"] = state ? state.patchId : undefined;
            inputs["patchModel"] = state ? state.patchModel : undefined;
            inputs["peerAutonomousContainerDatabaseBackupConfig"] = state ? state.peerAutonomousContainerDatabaseBackupConfig : undefined;
            inputs["peerAutonomousContainerDatabaseCompartmentId"] = state ? state.peerAutonomousContainerDatabaseCompartmentId : undefined;
            inputs["peerAutonomousContainerDatabaseDisplayName"] = state ? state.peerAutonomousContainerDatabaseDisplayName : undefined;
            inputs["peerAutonomousExadataInfrastructureId"] = state ? state.peerAutonomousExadataInfrastructureId : undefined;
            inputs["peerAutonomousVmClusterId"] = state ? state.peerAutonomousVmClusterId : undefined;
            inputs["peerDbUniqueName"] = state ? state.peerDbUniqueName : undefined;
            inputs["protectionMode"] = state ? state.protectionMode : undefined;
            inputs["role"] = state ? state.role : undefined;
            inputs["rotateKeyTrigger"] = state ? state.rotateKeyTrigger : undefined;
            inputs["serviceLevelAgreementType"] = state ? state.serviceLevelAgreementType : undefined;
            inputs["standbyMaintenanceBufferInDays"] = state ? state.standbyMaintenanceBufferInDays : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["vaultId"] = state ? state.vaultId : undefined;
        } else {
            const args = argsOrState as AutonomousContainerDatabaseArgs | undefined;
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.patchModel === undefined) && !opts.urn) {
                throw new Error("Missing required property 'patchModel'");
            }
            inputs["autonomousExadataInfrastructureId"] = args ? args.autonomousExadataInfrastructureId : undefined;
            inputs["autonomousVmClusterId"] = args ? args.autonomousVmClusterId : undefined;
            inputs["backupConfig"] = args ? args.backupConfig : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["dbUniqueName"] = args ? args.dbUniqueName : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["keyStoreId"] = args ? args.keyStoreId : undefined;
            inputs["kmsKeyId"] = args ? args.kmsKeyId : undefined;
            inputs["maintenanceWindowDetails"] = args ? args.maintenanceWindowDetails : undefined;
            inputs["patchModel"] = args ? args.patchModel : undefined;
            inputs["peerAutonomousContainerDatabaseBackupConfig"] = args ? args.peerAutonomousContainerDatabaseBackupConfig : undefined;
            inputs["peerAutonomousContainerDatabaseCompartmentId"] = args ? args.peerAutonomousContainerDatabaseCompartmentId : undefined;
            inputs["peerAutonomousContainerDatabaseDisplayName"] = args ? args.peerAutonomousContainerDatabaseDisplayName : undefined;
            inputs["peerAutonomousExadataInfrastructureId"] = args ? args.peerAutonomousExadataInfrastructureId : undefined;
            inputs["peerAutonomousVmClusterId"] = args ? args.peerAutonomousVmClusterId : undefined;
            inputs["peerDbUniqueName"] = args ? args.peerDbUniqueName : undefined;
            inputs["protectionMode"] = args ? args.protectionMode : undefined;
            inputs["rotateKeyTrigger"] = args ? args.rotateKeyTrigger : undefined;
            inputs["serviceLevelAgreementType"] = args ? args.serviceLevelAgreementType : undefined;
            inputs["standbyMaintenanceBufferInDays"] = args ? args.standbyMaintenanceBufferInDays : undefined;
            inputs["vaultId"] = args ? args.vaultId : undefined;
            inputs["availabilityDomain"] = undefined /*out*/;
            inputs["dbVersion"] = undefined /*out*/;
            inputs["infrastructureType"] = undefined /*out*/;
            inputs["keyStoreWalletName"] = undefined /*out*/;
            inputs["lastMaintenanceRunId"] = undefined /*out*/;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["maintenanceWindow"] = undefined /*out*/;
            inputs["nextMaintenanceRunId"] = undefined /*out*/;
            inputs["patchId"] = undefined /*out*/;
            inputs["role"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(AutonomousContainerDatabase.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AutonomousContainerDatabase resources.
 */
export interface AutonomousContainerDatabaseState {
    /**
     * The OCID of the Autonomous Exadata Infrastructure.
     */
    autonomousExadataInfrastructureId?: pulumi.Input<string>;
    /**
     * The OCID of the Autonomous VM Cluster.
     */
    autonomousVmClusterId?: pulumi.Input<string>;
    /**
     * The availability domain of the Autonomous Container Database.
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * (Updatable) Backup options for the Autonomous Container Database.
     */
    backupConfig?: pulumi.Input<inputs.database.AutonomousContainerDatabaseBackupConfig>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Autonomous Container Database.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The `DB_UNIQUE_NAME` of the Oracle Database being backed up.
     */
    dbUniqueName?: pulumi.Input<string>;
    /**
     * Oracle Database version of the Autonomous Container Database.
     */
    dbVersion?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The display name for the Autonomous Container Database.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The infrastructure type this resource belongs to.
     */
    infrastructureType?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     */
    keyStoreId?: pulumi.Input<string>;
    /**
     * The wallet name for Oracle Key Vault.
     */
    keyStoreWalletName?: pulumi.Input<string>;
    /**
     * The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     */
    kmsKeyId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     */
    lastMaintenanceRunId?: pulumi.Input<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     */
    maintenanceWindow?: pulumi.Input<inputs.database.AutonomousContainerDatabaseMaintenanceWindow>;
    /**
     * (Updatable) The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     */
    maintenanceWindowDetails?: pulumi.Input<inputs.database.AutonomousContainerDatabaseMaintenanceWindowDetails>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     */
    nextMaintenanceRunId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch applied on the system.
     */
    patchId?: pulumi.Input<string>;
    /**
     * (Updatable) Database Patch model preference.
     */
    patchModel?: pulumi.Input<string>;
    peerAutonomousContainerDatabaseBackupConfig?: pulumi.Input<inputs.database.AutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the standby Autonomous Container Database will be created.
     */
    peerAutonomousContainerDatabaseCompartmentId?: pulumi.Input<string>;
    /**
     * The display name for the peer Autonomous Container Database.
     */
    peerAutonomousContainerDatabaseDisplayName?: pulumi.Input<string>;
    /**
     * The OCID of the peer Autonomous Exadata Infrastructure for autonomous dataguard.
     */
    peerAutonomousExadataInfrastructureId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous VM cluster for Autonomous Data Guard. Required to enable Data Guard.
     */
    peerAutonomousVmClusterId?: pulumi.Input<string>;
    /**
     * The `DB_UNIQUE_NAME` of the peer Autonomous Container Database in a Data Guard association.
     */
    peerDbUniqueName?: pulumi.Input<string>;
    /**
     * The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     */
    protectionMode?: pulumi.Input<string>;
    /**
     * The role of the dataguard enabled Autonomous Container Database.
     */
    role?: pulumi.Input<string>;
    /**
     * (Updatable) An optional property when flipped triggers rotation of KMS key. It is only applicable on dedicated container databases i.e. where `autonomousExadataInfrastructureId` is set.
     */
    rotateKeyTrigger?: pulumi.Input<boolean>;
    /**
     * The service level agreement type of the Autonomous Container Database. The default is STANDARD. For an autonomous dataguard Autonomous Container Database, the specified Autonomous Exadata Infrastructure must be associated with a remote Autonomous Exadata Infrastructure.
     */
    serviceLevelAgreementType?: pulumi.Input<string>;
    /**
     * (Updatable) The scheduling detail for the quarterly maintenance window of standby Autonomous Container Database. This value represents the number of days before the primary database maintenance schedule.
     */
    standbyMaintenanceBufferInDays?: pulumi.Input<number>;
    /**
     * The current state of the Autonomous Container Database.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the Autonomous Container Database was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     */
    vaultId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AutonomousContainerDatabase resource.
 */
export interface AutonomousContainerDatabaseArgs {
    /**
     * The OCID of the Autonomous Exadata Infrastructure.
     */
    autonomousExadataInfrastructureId?: pulumi.Input<string>;
    /**
     * The OCID of the Autonomous VM Cluster.
     */
    autonomousVmClusterId?: pulumi.Input<string>;
    /**
     * (Updatable) Backup options for the Autonomous Container Database.
     */
    backupConfig?: pulumi.Input<inputs.database.AutonomousContainerDatabaseBackupConfig>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Autonomous Container Database.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The `DB_UNIQUE_NAME` of the Oracle Database being backed up.
     */
    dbUniqueName?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The display name for the Autonomous Container Database.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     */
    keyStoreId?: pulumi.Input<string>;
    /**
     * The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     */
    kmsKeyId?: pulumi.Input<string>;
    /**
     * (Updatable) The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     */
    maintenanceWindowDetails?: pulumi.Input<inputs.database.AutonomousContainerDatabaseMaintenanceWindowDetails>;
    /**
     * (Updatable) Database Patch model preference.
     */
    patchModel: pulumi.Input<string>;
    peerAutonomousContainerDatabaseBackupConfig?: pulumi.Input<inputs.database.AutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the standby Autonomous Container Database will be created.
     */
    peerAutonomousContainerDatabaseCompartmentId?: pulumi.Input<string>;
    /**
     * The display name for the peer Autonomous Container Database.
     */
    peerAutonomousContainerDatabaseDisplayName?: pulumi.Input<string>;
    /**
     * The OCID of the peer Autonomous Exadata Infrastructure for autonomous dataguard.
     */
    peerAutonomousExadataInfrastructureId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous VM cluster for Autonomous Data Guard. Required to enable Data Guard.
     */
    peerAutonomousVmClusterId?: pulumi.Input<string>;
    /**
     * The `DB_UNIQUE_NAME` of the peer Autonomous Container Database in a Data Guard association.
     */
    peerDbUniqueName?: pulumi.Input<string>;
    /**
     * The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     */
    protectionMode?: pulumi.Input<string>;
    /**
     * (Updatable) An optional property when flipped triggers rotation of KMS key. It is only applicable on dedicated container databases i.e. where `autonomousExadataInfrastructureId` is set.
     */
    rotateKeyTrigger?: pulumi.Input<boolean>;
    /**
     * The service level agreement type of the Autonomous Container Database. The default is STANDARD. For an autonomous dataguard Autonomous Container Database, the specified Autonomous Exadata Infrastructure must be associated with a remote Autonomous Exadata Infrastructure.
     */
    serviceLevelAgreementType?: pulumi.Input<string>;
    /**
     * (Updatable) The scheduling detail for the quarterly maintenance window of standby Autonomous Container Database. This value represents the number of days before the primary database maintenance schedule.
     */
    standbyMaintenanceBufferInDays?: pulumi.Input<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     */
    vaultId?: pulumi.Input<string>;
}
