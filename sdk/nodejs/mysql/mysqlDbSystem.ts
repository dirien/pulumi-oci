// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Mysql Db System resource in Oracle Cloud Infrastructure MySQL Database service.
 *
 * Creates and launches a DB System.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMysqlDbSystem = new oci.mysql.MysqlDbSystem("testMysqlDbSystem", {
 *     adminPassword: _var.mysql_db_system_admin_password,
 *     adminUsername: _var.mysql_db_system_admin_username,
 *     availabilityDomain: _var.mysql_db_system_availability_domain,
 *     compartmentId: _var.compartment_id,
 *     shapeName: _var.mysql_shape_name,
 *     subnetId: oci_core_subnet.test_subnet.id,
 *     backupPolicy: {
 *         definedTags: {
 *             "foo-namespace.bar-key": "value",
 *         },
 *         freeformTags: {
 *             "bar-key": "value",
 *         },
 *         isEnabled: _var.mysql_db_system_backup_policy_is_enabled,
 *         retentionInDays: _var.mysql_db_system_backup_policy_retention_in_days,
 *         windowStartTime: _var.mysql_db_system_backup_policy_window_start_time,
 *     },
 *     configurationId: oci_audit_configuration.test_configuration.id,
 *     dataStorageSizeInGb: _var.mysql_db_system_data_storage_size_in_gb,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     description: _var.mysql_db_system_description,
 *     displayName: _var.mysql_db_system_display_name,
 *     faultDomain: _var.mysql_db_system_fault_domain,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     hostnameLabel: _var.mysql_db_system_hostname_label,
 *     ipAddress: _var.mysql_db_system_ip_address,
 *     isHighlyAvailable: _var.mysql_db_system_is_highly_available,
 *     maintenance: {
 *         windowStartTime: _var.mysql_db_system_maintenance_window_start_time,
 *     },
 *     port: _var.mysql_db_system_port,
 *     portX: _var.mysql_db_system_port_x,
 *     source: {
 *         sourceType: _var.mysql_db_system_source_source_type,
 *         backupId: oci_mysql_mysql_backup.test_backup.id,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * MysqlDbSystems can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:mysql/mysqlDbSystem:MysqlDbSystem test_mysql_db_system "id"
 * ```
 */
export class MysqlDbSystem extends pulumi.CustomResource {
    /**
     * Get an existing MysqlDbSystem resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MysqlDbSystemState, opts?: pulumi.CustomResourceOptions): MysqlDbSystem {
        return new MysqlDbSystem(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:mysql/mysqlDbSystem:MysqlDbSystem';

    /**
     * Returns true if the given object is an instance of MysqlDbSystem.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MysqlDbSystem {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MysqlDbSystem.__pulumiType;
    }

    /**
     * The password for the administrative user. The password must be between 8 and 32 characters long, and must contain at least 1 numeric character, 1 lowercase character, 1 uppercase character, and 1 special (nonalphanumeric) character.
     */
    public readonly adminPassword!: pulumi.Output<string>;
    /**
     * The username for the administrative user.
     */
    public readonly adminUsername!: pulumi.Output<string>;
    /**
     * DEPRECATED -- please use HeatWave API instead. A summary of an Analytics Cluster.
     */
    public /*out*/ readonly analyticsCluster!: pulumi.Output<outputs.mysql.MysqlDbSystemAnalyticsCluster>;
    /**
     * The availability domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     */
    public readonly availabilityDomain!: pulumi.Output<string>;
    /**
     * (Updatable) Backup policy as optionally used for DB System Creation.
     */
    public readonly backupPolicy!: pulumi.Output<outputs.mysql.MysqlDbSystemBackupPolicy>;
    /**
     * A list with a summary of all the Channels attached to the DB System.
     */
    public /*out*/ readonly channels!: pulumi.Output<outputs.mysql.MysqlDbSystemChannel[]>;
    /**
     * The OCID of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The OCID of the Configuration to be used for this DB System.
     */
    public readonly configurationId!: pulumi.Output<string>;
    /**
     * The availability domain and fault domain a DB System is placed in.
     */
    public /*out*/ readonly currentPlacement!: pulumi.Output<outputs.mysql.MysqlDbSystemCurrentPlacement>;
    /**
     * Initial size of the data volume in GBs that will be created and attached. Keep in mind that this only specifies the size of the database data volume, the log volume for the database will be scaled appropriately with its shape. It is required if you are creating a new database. It cannot be set if you are creating a database from a backup.
     */
    public readonly dataStorageSizeInGb!: pulumi.Output<number>;
    /**
     * (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) User-provided data about the DB System.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) The user-friendly name for the DB System. It does not have to be unique.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The network endpoints available for this DB System.
     */
    public /*out*/ readonly endpoints!: pulumi.Output<outputs.mysql.MysqlDbSystemEndpoint[]>;
    /**
     * The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     */
    public readonly faultDomain!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * A summary of a HeatWave cluster.
     */
    public /*out*/ readonly heatWaveCluster!: pulumi.Output<outputs.mysql.MysqlDbSystemHeatWaveCluster>;
    /**
     * The hostname for the primary endpoint of the DB System. Used for DNS.
     */
    public readonly hostnameLabel!: pulumi.Output<string>;
    /**
     * The IP address the DB System is configured to listen on. A private IP address of your choice to assign to the primary endpoint of the DB System. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns a private IP address from the subnet. This should be a "dotted-quad" style IPv4 address.
     */
    public readonly ipAddress!: pulumi.Output<string>;
    /**
     * DEPRECATED -- please use `isHeatWaveClusterAttached` instead. If the DB System has an Analytics Cluster attached.
     */
    public /*out*/ readonly isAnalyticsClusterAttached!: pulumi.Output<boolean>;
    /**
     * If the DB System has a HeatWave Cluster attached.
     */
    public /*out*/ readonly isHeatWaveClusterAttached!: pulumi.Output<boolean>;
    /**
     * (Updatable) Specifies if the DB System is highly available.
     */
    public readonly isHighlyAvailable!: pulumi.Output<boolean>;
    /**
     * Additional information about the current lifecycleState.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) The Maintenance Policy for the DB System. `maintenance` and `backupPolicy` cannot be updated in the same request.
     */
    public readonly maintenance!: pulumi.Output<outputs.mysql.MysqlDbSystemMaintenance>;
    /**
     * Name of the MySQL Version in use for the DB System.
     *
     * @deprecated The 'mysql_version' field has been deprecated and may be removed in a future version. Do not use this field.
     */
    public readonly mysqlVersion!: pulumi.Output<string>;
    /**
     * The port for primary endpoint of the DB System to listen on.
     */
    public readonly port!: pulumi.Output<number>;
    /**
     * The TCP network port on which X Plugin listens for connections. This is the X Plugin equivalent of port.
     */
    public readonly portX!: pulumi.Output<number>;
    /**
     * The name of the shape. The shape determines the resources allocated
     * * CPU cores and memory for VM shapes; CPU cores, memory and storage for non-VM (or bare metal) shapes. To get a list of shapes, use the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/mysql/20190415/ShapeSummary/ListShapes) operation.
     */
    public readonly shapeName!: pulumi.Output<string>;
    /**
     * It is applicable only for stopping a DB System. Could be set to `FAST`, `SLOW` or `IMMEDIATE`. Default value is `FAST`.
     */
    public readonly shutdownType!: pulumi.Output<string | undefined>;
    /**
     * Parameters detailing how to provision the initial data of the system.
     */
    public readonly source!: pulumi.Output<outputs.mysql.MysqlDbSystemSource>;
    /**
     * (Updatable) The target state for the DB System. Could be set to `ACTIVE` or `INACTIVE`.
     */
    public readonly state!: pulumi.Output<string>;
    /**
     * The OCID of the subnet the DB System is associated with.
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * The date and time the DB System was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the DB System was last updated.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a MysqlDbSystem resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MysqlDbSystemArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MysqlDbSystemArgs | MysqlDbSystemState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MysqlDbSystemState | undefined;
            inputs["adminPassword"] = state ? state.adminPassword : undefined;
            inputs["adminUsername"] = state ? state.adminUsername : undefined;
            inputs["analyticsCluster"] = state ? state.analyticsCluster : undefined;
            inputs["availabilityDomain"] = state ? state.availabilityDomain : undefined;
            inputs["backupPolicy"] = state ? state.backupPolicy : undefined;
            inputs["channels"] = state ? state.channels : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["configurationId"] = state ? state.configurationId : undefined;
            inputs["currentPlacement"] = state ? state.currentPlacement : undefined;
            inputs["dataStorageSizeInGb"] = state ? state.dataStorageSizeInGb : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["endpoints"] = state ? state.endpoints : undefined;
            inputs["faultDomain"] = state ? state.faultDomain : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["heatWaveCluster"] = state ? state.heatWaveCluster : undefined;
            inputs["hostnameLabel"] = state ? state.hostnameLabel : undefined;
            inputs["ipAddress"] = state ? state.ipAddress : undefined;
            inputs["isAnalyticsClusterAttached"] = state ? state.isAnalyticsClusterAttached : undefined;
            inputs["isHeatWaveClusterAttached"] = state ? state.isHeatWaveClusterAttached : undefined;
            inputs["isHighlyAvailable"] = state ? state.isHighlyAvailable : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["maintenance"] = state ? state.maintenance : undefined;
            inputs["mysqlVersion"] = state ? state.mysqlVersion : undefined;
            inputs["port"] = state ? state.port : undefined;
            inputs["portX"] = state ? state.portX : undefined;
            inputs["shapeName"] = state ? state.shapeName : undefined;
            inputs["shutdownType"] = state ? state.shutdownType : undefined;
            inputs["source"] = state ? state.source : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["subnetId"] = state ? state.subnetId : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as MysqlDbSystemArgs | undefined;
            if ((!args || args.adminPassword === undefined) && !opts.urn) {
                throw new Error("Missing required property 'adminPassword'");
            }
            if ((!args || args.adminUsername === undefined) && !opts.urn) {
                throw new Error("Missing required property 'adminUsername'");
            }
            if ((!args || args.availabilityDomain === undefined) && !opts.urn) {
                throw new Error("Missing required property 'availabilityDomain'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.shapeName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'shapeName'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            inputs["adminPassword"] = args ? args.adminPassword : undefined;
            inputs["adminUsername"] = args ? args.adminUsername : undefined;
            inputs["availabilityDomain"] = args ? args.availabilityDomain : undefined;
            inputs["backupPolicy"] = args ? args.backupPolicy : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["configurationId"] = args ? args.configurationId : undefined;
            inputs["dataStorageSizeInGb"] = args ? args.dataStorageSizeInGb : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["faultDomain"] = args ? args.faultDomain : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["hostnameLabel"] = args ? args.hostnameLabel : undefined;
            inputs["ipAddress"] = args ? args.ipAddress : undefined;
            inputs["isHighlyAvailable"] = args ? args.isHighlyAvailable : undefined;
            inputs["maintenance"] = args ? args.maintenance : undefined;
            inputs["mysqlVersion"] = args ? args.mysqlVersion : undefined;
            inputs["port"] = args ? args.port : undefined;
            inputs["portX"] = args ? args.portX : undefined;
            inputs["shapeName"] = args ? args.shapeName : undefined;
            inputs["shutdownType"] = args ? args.shutdownType : undefined;
            inputs["source"] = args ? args.source : undefined;
            inputs["state"] = args ? args.state : undefined;
            inputs["subnetId"] = args ? args.subnetId : undefined;
            inputs["analyticsCluster"] = undefined /*out*/;
            inputs["channels"] = undefined /*out*/;
            inputs["currentPlacement"] = undefined /*out*/;
            inputs["endpoints"] = undefined /*out*/;
            inputs["heatWaveCluster"] = undefined /*out*/;
            inputs["isAnalyticsClusterAttached"] = undefined /*out*/;
            inputs["isHeatWaveClusterAttached"] = undefined /*out*/;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeUpdated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(MysqlDbSystem.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MysqlDbSystem resources.
 */
export interface MysqlDbSystemState {
    /**
     * The password for the administrative user. The password must be between 8 and 32 characters long, and must contain at least 1 numeric character, 1 lowercase character, 1 uppercase character, and 1 special (nonalphanumeric) character.
     */
    adminPassword?: pulumi.Input<string>;
    /**
     * The username for the administrative user.
     */
    adminUsername?: pulumi.Input<string>;
    /**
     * DEPRECATED -- please use HeatWave API instead. A summary of an Analytics Cluster.
     */
    analyticsCluster?: pulumi.Input<inputs.mysql.MysqlDbSystemAnalyticsCluster>;
    /**
     * The availability domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * (Updatable) Backup policy as optionally used for DB System Creation.
     */
    backupPolicy?: pulumi.Input<inputs.mysql.MysqlDbSystemBackupPolicy>;
    /**
     * A list with a summary of all the Channels attached to the DB System.
     */
    channels?: pulumi.Input<pulumi.Input<inputs.mysql.MysqlDbSystemChannel>[]>;
    /**
     * The OCID of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The OCID of the Configuration to be used for this DB System.
     */
    configurationId?: pulumi.Input<string>;
    /**
     * The availability domain and fault domain a DB System is placed in.
     */
    currentPlacement?: pulumi.Input<inputs.mysql.MysqlDbSystemCurrentPlacement>;
    /**
     * Initial size of the data volume in GBs that will be created and attached. Keep in mind that this only specifies the size of the database data volume, the log volume for the database will be scaled appropriately with its shape. It is required if you are creating a new database. It cannot be set if you are creating a database from a backup.
     */
    dataStorageSizeInGb?: pulumi.Input<number>;
    /**
     * (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) User-provided data about the DB System.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The user-friendly name for the DB System. It does not have to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The network endpoints available for this DB System.
     */
    endpoints?: pulumi.Input<pulumi.Input<inputs.mysql.MysqlDbSystemEndpoint>[]>;
    /**
     * The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     */
    faultDomain?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A summary of a HeatWave cluster.
     */
    heatWaveCluster?: pulumi.Input<inputs.mysql.MysqlDbSystemHeatWaveCluster>;
    /**
     * The hostname for the primary endpoint of the DB System. Used for DNS.
     */
    hostnameLabel?: pulumi.Input<string>;
    /**
     * The IP address the DB System is configured to listen on. A private IP address of your choice to assign to the primary endpoint of the DB System. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns a private IP address from the subnet. This should be a "dotted-quad" style IPv4 address.
     */
    ipAddress?: pulumi.Input<string>;
    /**
     * DEPRECATED -- please use `isHeatWaveClusterAttached` instead. If the DB System has an Analytics Cluster attached.
     */
    isAnalyticsClusterAttached?: pulumi.Input<boolean>;
    /**
     * If the DB System has a HeatWave Cluster attached.
     */
    isHeatWaveClusterAttached?: pulumi.Input<boolean>;
    /**
     * (Updatable) Specifies if the DB System is highly available.
     */
    isHighlyAvailable?: pulumi.Input<boolean>;
    /**
     * Additional information about the current lifecycleState.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The Maintenance Policy for the DB System. `maintenance` and `backupPolicy` cannot be updated in the same request.
     */
    maintenance?: pulumi.Input<inputs.mysql.MysqlDbSystemMaintenance>;
    /**
     * Name of the MySQL Version in use for the DB System.
     *
     * @deprecated The 'mysql_version' field has been deprecated and may be removed in a future version. Do not use this field.
     */
    mysqlVersion?: pulumi.Input<string>;
    /**
     * The port for primary endpoint of the DB System to listen on.
     */
    port?: pulumi.Input<number>;
    /**
     * The TCP network port on which X Plugin listens for connections. This is the X Plugin equivalent of port.
     */
    portX?: pulumi.Input<number>;
    /**
     * The name of the shape. The shape determines the resources allocated
     * * CPU cores and memory for VM shapes; CPU cores, memory and storage for non-VM (or bare metal) shapes. To get a list of shapes, use the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/mysql/20190415/ShapeSummary/ListShapes) operation.
     */
    shapeName?: pulumi.Input<string>;
    /**
     * It is applicable only for stopping a DB System. Could be set to `FAST`, `SLOW` or `IMMEDIATE`. Default value is `FAST`.
     */
    shutdownType?: pulumi.Input<string>;
    /**
     * Parameters detailing how to provision the initial data of the system.
     */
    source?: pulumi.Input<inputs.mysql.MysqlDbSystemSource>;
    /**
     * (Updatable) The target state for the DB System. Could be set to `ACTIVE` or `INACTIVE`.
     */
    state?: pulumi.Input<string>;
    /**
     * The OCID of the subnet the DB System is associated with.
     */
    subnetId?: pulumi.Input<string>;
    /**
     * The date and time the DB System was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the DB System was last updated.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a MysqlDbSystem resource.
 */
export interface MysqlDbSystemArgs {
    /**
     * The password for the administrative user. The password must be between 8 and 32 characters long, and must contain at least 1 numeric character, 1 lowercase character, 1 uppercase character, and 1 special (nonalphanumeric) character.
     */
    adminPassword: pulumi.Input<string>;
    /**
     * The username for the administrative user.
     */
    adminUsername: pulumi.Input<string>;
    /**
     * The availability domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     */
    availabilityDomain: pulumi.Input<string>;
    /**
     * (Updatable) Backup policy as optionally used for DB System Creation.
     */
    backupPolicy?: pulumi.Input<inputs.mysql.MysqlDbSystemBackupPolicy>;
    /**
     * The OCID of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The OCID of the Configuration to be used for this DB System.
     */
    configurationId?: pulumi.Input<string>;
    /**
     * Initial size of the data volume in GBs that will be created and attached. Keep in mind that this only specifies the size of the database data volume, the log volume for the database will be scaled appropriately with its shape. It is required if you are creating a new database. It cannot be set if you are creating a database from a backup.
     */
    dataStorageSizeInGb?: pulumi.Input<number>;
    /**
     * (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) User-provided data about the DB System.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The user-friendly name for the DB System. It does not have to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     */
    faultDomain?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The hostname for the primary endpoint of the DB System. Used for DNS.
     */
    hostnameLabel?: pulumi.Input<string>;
    /**
     * The IP address the DB System is configured to listen on. A private IP address of your choice to assign to the primary endpoint of the DB System. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns a private IP address from the subnet. This should be a "dotted-quad" style IPv4 address.
     */
    ipAddress?: pulumi.Input<string>;
    /**
     * (Updatable) Specifies if the DB System is highly available.
     */
    isHighlyAvailable?: pulumi.Input<boolean>;
    /**
     * (Updatable) The Maintenance Policy for the DB System. `maintenance` and `backupPolicy` cannot be updated in the same request.
     */
    maintenance?: pulumi.Input<inputs.mysql.MysqlDbSystemMaintenance>;
    /**
     * Name of the MySQL Version in use for the DB System.
     *
     * @deprecated The 'mysql_version' field has been deprecated and may be removed in a future version. Do not use this field.
     */
    mysqlVersion?: pulumi.Input<string>;
    /**
     * The port for primary endpoint of the DB System to listen on.
     */
    port?: pulumi.Input<number>;
    /**
     * The TCP network port on which X Plugin listens for connections. This is the X Plugin equivalent of port.
     */
    portX?: pulumi.Input<number>;
    /**
     * The name of the shape. The shape determines the resources allocated
     * * CPU cores and memory for VM shapes; CPU cores, memory and storage for non-VM (or bare metal) shapes. To get a list of shapes, use the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/mysql/20190415/ShapeSummary/ListShapes) operation.
     */
    shapeName: pulumi.Input<string>;
    /**
     * It is applicable only for stopping a DB System. Could be set to `FAST`, `SLOW` or `IMMEDIATE`. Default value is `FAST`.
     */
    shutdownType?: pulumi.Input<string>;
    /**
     * Parameters detailing how to provision the initial data of the system.
     */
    source?: pulumi.Input<inputs.mysql.MysqlDbSystemSource>;
    /**
     * (Updatable) The target state for the DB System. Could be set to `ACTIVE` or `INACTIVE`.
     */
    state?: pulumi.Input<string>;
    /**
     * The OCID of the subnet the DB System is associated with.
     */
    subnetId: pulumi.Input<string>;
}
