// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Mysql Db System resource in Oracle Cloud Infrastructure MySQL Database service.
 *
 * Get information about the specified DB System.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMysqlDbSystem = oci.mysql.getMysqlDbSystem({
 *     dbSystemId: oci_mysql_mysql_db_system.test_db_system.id,
 * });
 * ```
 */
export function getMysqlDbSystem(args: GetMysqlDbSystemArgs, opts?: pulumi.InvokeOptions): Promise<GetMysqlDbSystemResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:mysql/getMysqlDbSystem:getMysqlDbSystem", {
        "dbSystemId": args.dbSystemId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMysqlDbSystem.
 */
export interface GetMysqlDbSystemArgs {
    /**
     * The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbSystemId: string;
}

/**
 * A collection of values returned by getMysqlDbSystem.
 */
export interface GetMysqlDbSystemResult {
    readonly adminPassword: string;
    readonly adminUsername: string;
    /**
     * DEPRECATED -- please use HeatWave API instead. A summary of an Analytics Cluster.
     */
    readonly analyticsCluster: outputs.mysql.GetMysqlDbSystemAnalyticsCluster;
    /**
     * The availability domain in which the DB System is placed.
     */
    readonly availabilityDomain: string;
    /**
     * The Backup policy for the DB System.
     */
    readonly backupPolicy: outputs.mysql.GetMysqlDbSystemBackupPolicy;
    /**
     * A list with a summary of all the Channels attached to the DB System.
     */
    readonly channels: outputs.mysql.GetMysqlDbSystemChannel[];
    /**
     * The OCID of the compartment the DB System belongs in.
     */
    readonly compartmentId: string;
    /**
     * The OCID of the Configuration to be used for Instances in this DB System.
     */
    readonly configurationId: string;
    /**
     * The availability domain and fault domain a DB System is placed in.
     */
    readonly currentPlacement: outputs.mysql.GetMysqlDbSystemCurrentPlacement;
    /**
     * Initial size of the data volume in GiBs that will be created and attached.
     */
    readonly dataStorageSizeInGb: number;
    /**
     * The OCID of the source DB System.
     */
    readonly dbSystemId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * User-provided data about the DB System.
     */
    readonly description: string;
    /**
     * The user-friendly name for the DB System. It does not have to be unique.
     */
    readonly displayName: string;
    /**
     * The network endpoints available for this DB System.
     */
    readonly endpoints: outputs.mysql.GetMysqlDbSystemEndpoint[];
    /**
     * The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     */
    readonly faultDomain: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * A summary of a HeatWave cluster.
     */
    readonly heatWaveCluster: outputs.mysql.GetMysqlDbSystemHeatWaveCluster;
    /**
     * The hostname for the primary endpoint of the DB System. Used for DNS. The value is the hostname portion of the primary private IP's fully qualified domain name (FQDN) (for example, "dbsystem-1" in FQDN "dbsystem-1.subnet123.vcn1.oraclevcn.com"). Must be unique across all VNICs in the subnet and comply with RFC 952 and RFC 1123.
     */
    readonly hostnameLabel: string;
    /**
     * The OCID of the DB System.
     */
    readonly id: string;
    /**
     * The IP address the DB System is configured to listen on. A private IP address of the primary endpoint of the DB System. Must be an available IP address within the subnet's CIDR. This will be a "dotted-quad" style IPv4 address.
     */
    readonly ipAddress: string;
    /**
     * DEPRECATED -- please use `isHeatWaveClusterAttached` instead. If the DB System has an Analytics Cluster attached.
     */
    readonly isAnalyticsClusterAttached: boolean;
    /**
     * If the DB System has a HeatWave Cluster attached.
     */
    readonly isHeatWaveClusterAttached: boolean;
    /**
     * If the policy is to enable high availability of the instance, by maintaining secondary/failover capacity as necessary.
     */
    readonly isHighlyAvailable: boolean;
    /**
     * Additional information about the current lifecycleState.
     */
    readonly lifecycleDetails: string;
    /**
     * The Maintenance Policy for the DB System.
     */
    readonly maintenance: outputs.mysql.GetMysqlDbSystemMaintenance;
    /**
     * Name of the MySQL Version in use for the DB System.
     *
     * @deprecated The 'mysql_version' field has been deprecated and may be removed in a future version. Do not use this field.
     */
    readonly mysqlVersion: string;
    /**
     * The port for primary endpoint of the DB System to listen on.
     */
    readonly port: number;
    /**
     * The network port on which X Plugin listens for TCP/IP connections. This is the X Plugin equivalent of port.
     */
    readonly portX: number;
    /**
     * The shape of the primary instances of the DB System. The shape determines resources allocated to a DB System - CPU cores and memory for VM shapes; CPU cores, memory and storage for non-VM (or bare metal) shapes. To get a list of shapes, use (the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/mysql/20181021/ShapeSummary/ListShapes) operation.
     */
    readonly shapeName: string;
    readonly shutdownType: string;
    /**
     * Parameters detailing how to provision the initial data of the DB System.
     */
    readonly source: outputs.mysql.GetMysqlDbSystemSource;
    /**
     * The current state of the DB System.
     */
    readonly state: string;
    /**
     * The OCID of the subnet the DB System is associated with.
     */
    readonly subnetId: string;
    /**
     * The date and time the DB System was created.
     */
    readonly timeCreated: string;
    /**
     * The time the DB System was last updated.
     */
    readonly timeUpdated: string;
}
