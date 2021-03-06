// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Enterprise Manager Bridges in Oracle Cloud Infrastructure Opsi service.
 *
 * Gets a list of Operations Insights Enterprise Manager bridges. Either compartmentId or id must be specified.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testEnterpriseManagerBridges = oci.opsi.getEnterpriseManagerBridges({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.enterprise_manager_bridge_display_name,
 *     id: _var.enterprise_manager_bridge_id,
 *     states: _var.enterprise_manager_bridge_state,
 * });
 * ```
 */
export function getEnterpriseManagerBridges(args?: GetEnterpriseManagerBridgesArgs, opts?: pulumi.InvokeOptions): Promise<GetEnterpriseManagerBridgesResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:opsi/getEnterpriseManagerBridges:getEnterpriseManagerBridges", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "states": args.states,
    }, opts);
}

/**
 * A collection of arguments for invoking getEnterpriseManagerBridges.
 */
export interface GetEnterpriseManagerBridgesArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: string;
    /**
     * A filter to return only resources that match the entire display name.
     */
    displayName?: string;
    filters?: inputs.opsi.GetEnterpriseManagerBridgesFilter[];
    /**
     * Unique Enterprise Manager bridge identifier
     */
    id?: string;
    /**
     * Lifecycle states
     */
    states?: string[];
}

/**
 * A collection of values returned by getEnterpriseManagerBridges.
 */
export interface GetEnterpriseManagerBridgesResult {
    /**
     * Compartment identifier of the Enterprise Manager bridge
     */
    readonly compartmentId?: string;
    /**
     * User-friedly name of Enterprise Manager Bridge that does not have to be unique.
     */
    readonly displayName?: string;
    /**
     * The list of enterprise_manager_bridge_collection.
     */
    readonly enterpriseManagerBridgeCollections: outputs.opsi.GetEnterpriseManagerBridgesEnterpriseManagerBridgeCollection[];
    readonly filters?: outputs.opsi.GetEnterpriseManagerBridgesFilter[];
    /**
     * Enterprise Manager bridge identifier
     */
    readonly id?: string;
    /**
     * The current state of the Enterprise Manager bridge.
     */
    readonly states?: string[];
}
