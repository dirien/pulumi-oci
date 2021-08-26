// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Log Analytics Entities in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Return a list of log analytics entities.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testLogAnalyticsEntities = oci.loganalytics.getLogAnalyticsEntities({
 *     compartmentId: _var.compartment_id,
 *     namespace: _var.log_analytics_entity_namespace,
 *     cloudResourceId: oci_log_analytics_cloud_resource.test_cloud_resource.id,
 *     entityTypeNames: _var.log_analytics_entity_entity_type_name,
 *     hostname: _var.log_analytics_entity_hostname,
 *     hostnameContains: _var.log_analytics_entity_hostname_contains,
 *     isManagementAgentIdNull: _var.log_analytics_entity_is_management_agent_id_null,
 *     lifecycleDetailsContains: _var.log_analytics_entity_lifecycle_details_contains,
 *     name: _var.log_analytics_entity_name,
 *     nameContains: _var.log_analytics_entity_name_contains,
 *     sourceId: oci_log_analytics_source.test_source.id,
 *     state: _var.log_analytics_entity_state,
 * });
 * ```
 */
export function getLogAnalyticsEntities(args: GetLogAnalyticsEntitiesArgs, opts?: pulumi.InvokeOptions): Promise<GetLogAnalyticsEntitiesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:loganalytics/getLogAnalyticsEntities:getLogAnalyticsEntities", {
        "cloudResourceId": args.cloudResourceId,
        "compartmentId": args.compartmentId,
        "entityTypeNames": args.entityTypeNames,
        "filters": args.filters,
        "hostname": args.hostname,
        "hostnameContains": args.hostnameContains,
        "isManagementAgentIdNull": args.isManagementAgentIdNull,
        "lifecycleDetailsContains": args.lifecycleDetailsContains,
        "name": args.name,
        "nameContains": args.nameContains,
        "namespace": args.namespace,
        "sourceId": args.sourceId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getLogAnalyticsEntities.
 */
export interface GetLogAnalyticsEntitiesArgs {
    /**
     * A filter to return only log analytics entities whose cloudResourceId matches the cloudResourceId given.
     */
    cloudResourceId?: string;
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A filter to return only log analytics entities whose entityTypeName matches the entire log analytics entity type name of one of the entityTypeNames given in the list. The match is case-insensitive.
     */
    entityTypeNames?: string[];
    filters?: inputs.loganalytics.GetLogAnalyticsEntitiesFilter[];
    /**
     * A filter to return only log analytics entities whose hostname matches the entire hostname given.
     */
    hostname?: string;
    /**
     * A filter to return only log analytics entities whose hostname contains the substring given. The match is case-insensitive.
     */
    hostnameContains?: string;
    /**
     * A filter to return only those log analytics entities whose managementAgentId is null or is not null.
     */
    isManagementAgentIdNull?: string;
    /**
     * A filter to return only log analytics entities whose lifecycleDetails contains the specified string.
     */
    lifecycleDetailsContains?: string;
    /**
     * A filter to return only log analytics entities whose name matches the entire name given. The match is case-insensitive.
     */
    name?: string;
    /**
     * A filter to return only log analytics entities whose name contains the name given. The match is case-insensitive.
     */
    nameContains?: string;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: string;
    /**
     * A filter to return only log analytics entities whose sourceId matches the sourceId given.
     */
    sourceId?: string;
    /**
     * A filter to return only those log analytics entities with the specified lifecycle state. The state value is case-insensitive.
     */
    state?: string;
}

/**
 * A collection of values returned by getLogAnalyticsEntities.
 */
export interface GetLogAnalyticsEntitiesResult {
    /**
     * The OCID of the Cloud resource which this entity is a representation of. This may be blank when the entity represents a non-cloud resource that the customer may have on their premises.
     */
    readonly cloudResourceId?: string;
    /**
     * Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly compartmentId: string;
    /**
     * Log analytics entity type name.
     */
    readonly entityTypeNames?: string[];
    readonly filters?: outputs.loganalytics.GetLogAnalyticsEntitiesFilter[];
    /**
     * The hostname where the entity represented here is actually present. This would be the output one would get if they run `echo $HOSTNAME` on Linux or an equivalent OS command. This may be different from management agents host since logs may be collected remotely.
     */
    readonly hostname?: string;
    readonly hostnameContains?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly isManagementAgentIdNull?: string;
    readonly lifecycleDetailsContains?: string;
    /**
     * The list of log_analytics_entity_collection.
     */
    readonly logAnalyticsEntityCollections: outputs.loganalytics.GetLogAnalyticsEntitiesLogAnalyticsEntityCollection[];
    /**
     * Log analytics entity name.
     */
    readonly name?: string;
    readonly nameContains?: string;
    readonly namespace: string;
    /**
     * This indicates the type of source. It is primarily for Enterprise Manager Repository ID.
     */
    readonly sourceId?: string;
    /**
     * The current state of the log analytics entity.
     */
    readonly state?: string;
}
