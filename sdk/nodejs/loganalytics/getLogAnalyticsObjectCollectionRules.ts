// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Log Analytics Object Collection Rules in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Gets list of configuration details of Object Storage based collection rules.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testLogAnalyticsObjectCollectionRules = oci.loganalytics.getLogAnalyticsObjectCollectionRules({
 *     compartmentId: _var.compartment_id,
 *     namespace: _var.log_analytics_object_collection_rule_namespace,
 *     name: _var.log_analytics_object_collection_rule_name,
 *     state: _var.log_analytics_object_collection_rule_state,
 * });
 * ```
 */
export function getLogAnalyticsObjectCollectionRules(args: GetLogAnalyticsObjectCollectionRulesArgs, opts?: pulumi.InvokeOptions): Promise<GetLogAnalyticsObjectCollectionRulesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:loganalytics/getLogAnalyticsObjectCollectionRules:getLogAnalyticsObjectCollectionRules", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "name": args.name,
        "namespace": args.namespace,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getLogAnalyticsObjectCollectionRules.
 */
export interface GetLogAnalyticsObjectCollectionRulesArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    filters?: inputs.loganalytics.GetLogAnalyticsObjectCollectionRulesFilter[];
    /**
     * A filter to return rules only matching with this name.
     */
    name?: string;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: string;
    /**
     * Lifecycle state filter.
     */
    state?: string;
}

/**
 * A collection of values returned by getLogAnalyticsObjectCollectionRules.
 */
export interface GetLogAnalyticsObjectCollectionRulesResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.loganalytics.GetLogAnalyticsObjectCollectionRulesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of log_analytics_object_collection_rule_collection.
     */
    readonly logAnalyticsObjectCollectionRuleCollections: outputs.loganalytics.GetLogAnalyticsObjectCollectionRulesLogAnalyticsObjectCollectionRuleCollection[];
    /**
     * A unique name to the rule. The name must be unique, within the tenancy, and cannot be changed.
     */
    readonly name?: string;
    readonly namespace: string;
    /**
     * The current state of the rule.
     */
    readonly state?: string;
}
