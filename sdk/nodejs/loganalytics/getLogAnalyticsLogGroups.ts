// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Log Analytics Log Groups in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Returns a list of log groups in a compartment. You may limit the number of log groups, provide sorting options, and filter the results by specifying a display name.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testLogAnalyticsLogGroups = oci.loganalytics.getLogAnalyticsLogGroups({
 *     compartmentId: _var.compartment_id,
 *     namespace: _var.log_analytics_log_group_namespace,
 *     displayName: _var.log_analytics_log_group_display_name,
 * });
 * ```
 */
export function getLogAnalyticsLogGroups(args: GetLogAnalyticsLogGroupsArgs, opts?: pulumi.InvokeOptions): Promise<GetLogAnalyticsLogGroupsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:loganalytics/getLogAnalyticsLogGroups:getLogAnalyticsLogGroups", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "namespace": args.namespace,
    }, opts);
}

/**
 * A collection of arguments for invoking getLogAnalyticsLogGroups.
 */
export interface GetLogAnalyticsLogGroupsArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A filter to return only log analytics log groups whose displayName matches the entire display name given. The match is case-insensitive.
     */
    displayName?: string;
    filters?: inputs.loganalytics.GetLogAnalyticsLogGroupsFilter[];
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: string;
}

/**
 * A collection of values returned by getLogAnalyticsLogGroups.
 */
export interface GetLogAnalyticsLogGroupsResult {
    /**
     * Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
     */
    readonly displayName?: string;
    readonly filters?: outputs.loganalytics.GetLogAnalyticsLogGroupsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of log_analytics_log_group_summary_collection.
     */
    readonly logAnalyticsLogGroupSummaryCollections: outputs.loganalytics.GetLogAnalyticsLogGroupsLogAnalyticsLogGroupSummaryCollection[];
    readonly namespace: string;
}
