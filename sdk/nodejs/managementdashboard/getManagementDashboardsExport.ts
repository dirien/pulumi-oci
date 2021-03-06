// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Management Dashboards Export resource in Oracle Cloud Infrastructure Management Dashboard service.
 *
 * Exports an array of dashboards and their saved searches. Export is designed to work with importDashboard. An example using Oracle Cloud Infrastructure CLI is $oci management-dashboard dashboard export --query data --export-dashboard-id "{\"dashboardIds\":[\"ocid1.managementdashboard.oc1..dashboardId1\"]}"  > dashboards.json $oci management-dashboard dashboard import --from-json file://dashboards.json
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagementDashboardsExport = oci.managementdashboard.getManagementDashboardsExport({
 *     exportDashboardId: oci_management_dashboard_export_dashboard.test_export_dashboard.id,
 * });
 * ```
 */
export function getManagementDashboardsExport(args: GetManagementDashboardsExportArgs, opts?: pulumi.InvokeOptions): Promise<GetManagementDashboardsExportResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:managementdashboard/getManagementDashboardsExport:getManagementDashboardsExport", {
        "exportDashboardId": args.exportDashboardId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagementDashboardsExport.
 */
export interface GetManagementDashboardsExportArgs {
    /**
     * List of dashboardIds in plain text. The syntaxt is '{"dashboardIds":["dashboardId1", "dashboardId2", ...]}'. Escaping is needed when using in Oracle Cloud Infrastructure CLI. For example, "{\"dashboardIds\":[\"ocid1.managementdashboard.oc1..dashboardId1\"]}" .
     */
    exportDashboardId: string;
}

/**
 * A collection of values returned by getManagementDashboardsExport.
 */
export interface GetManagementDashboardsExportResult {
    readonly exportDashboardId: string;
    /**
     * String containing Array of Dashboards exported, check [ManagementDashboardExportDetails](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/managementdashboard/20200901/datatypes/ManagementDashboardExportDetails) for exact contents in the string value. The value of `exportDetails` can be used to pass as `importDetails` (CompartmentIds may have to be changed) in `oci.managementdashboard.ManagementDashboardsImport` resource.
     */
    readonly exportDetails: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
