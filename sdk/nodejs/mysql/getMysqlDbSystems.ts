// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Mysql Db Systems in Oracle Cloud Infrastructure MySQL Database service.
 *
 * Get a list of DB Systems in the specified compartment.
 * The default sort order is by timeUpdated, descending.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMysqlDbSystems = oci.mysql.getMysqlDbSystems({
 *     compartmentId: _var.compartment_id,
 *     configurationId: _var.mysql_configuration_id,
 *     dbSystemId: oci_mysql_mysql_db_system.test_db_system.id,
 *     displayName: _var.mysql_db_system_display_name,
 *     isAnalyticsClusterAttached: _var.mysql_db_system_is_analytics_cluster_attached,
 *     isHeatWaveClusterAttached: _var.mysql_db_system_is_heat_wave_cluster_attached,
 *     isUpToDate: _var.mysql_db_system_is_up_to_date,
 *     state: _var.mysql_db_system_state,
 * });
 * ```
 */
export function getMysqlDbSystems(args: GetMysqlDbSystemsArgs, opts?: pulumi.InvokeOptions): Promise<GetMysqlDbSystemsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:mysql/getMysqlDbSystems:getMysqlDbSystems", {
        "compartmentId": args.compartmentId,
        "configurationId": args.configurationId,
        "dbSystemId": args.dbSystemId,
        "displayName": args.displayName,
        "filters": args.filters,
        "isAnalyticsClusterAttached": args.isAnalyticsClusterAttached,
        "isHeatWaveClusterAttached": args.isHeatWaveClusterAttached,
        "isUpToDate": args.isUpToDate,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getMysqlDbSystems.
 */
export interface GetMysqlDbSystemsArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * The requested Configuration instance.
     */
    configurationId?: string;
    /**
     * The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbSystemId?: string;
    /**
     * A filter to return only the resource matching the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.mysql.GetMysqlDbSystemsFilter[];
    /**
     * DEPRECATED -- please use HeatWave API instead. If true, return only DB Systems with an Analytics Cluster attached, if false return only DB Systems with no Analytics Cluster attached. If not present, return all DB Systems.
     */
    isAnalyticsClusterAttached?: boolean;
    /**
     * If true, return only DB Systems with a HeatWave cluster attached, if false return only DB Systems with no HeatWave cluster attached. If not present, return all DB Systems.
     */
    isHeatWaveClusterAttached?: boolean;
    /**
     * Filter instances if they are using the latest revision of the Configuration they are associated with.
     */
    isUpToDate?: boolean;
    /**
     * DbSystem Lifecycle State
     */
    state?: string;
}

/**
 * A collection of values returned by getMysqlDbSystems.
 */
export interface GetMysqlDbSystemsResult {
    /**
     * The OCID of the compartment the DB System belongs in.
     */
    readonly compartmentId: string;
    /**
     * The OCID of the Configuration to be used for Instances in this DB System.
     */
    readonly configurationId?: string;
    /**
     * The OCID of the source DB System.
     */
    readonly dbSystemId?: string;
    /**
     * The list of db_systems.
     */
    readonly dbSystems: outputs.mysql.GetMysqlDbSystemsDbSystem[];
    /**
     * The user-friendly name for the DB System. It does not have to be unique.
     */
    readonly displayName?: string;
    readonly filters?: outputs.mysql.GetMysqlDbSystemsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * DEPRECATED -- please use `isHeatWaveClusterAttached` instead. If the DB System has an Analytics Cluster attached.
     */
    readonly isAnalyticsClusterAttached?: boolean;
    /**
     * If the DB System has a HeatWave Cluster attached.
     */
    readonly isHeatWaveClusterAttached?: boolean;
    readonly isUpToDate?: boolean;
    /**
     * The current state of the DB System.
     */
    readonly state?: string;
}
