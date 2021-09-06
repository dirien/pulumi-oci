// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Enterprise Manager Bridge resource in Oracle Cloud Infrastructure Opsi service.
 *
 * Gets details of an Operations Insights Enterprise Manager bridge.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testEnterpriseManagerBridge = oci.opsi.getEnterpriseManagerBridge({
 *     enterpriseManagerBridgeId: oci_opsi_enterprise_manager_bridge.test_enterprise_manager_bridge.id,
 * });
 * ```
 */
export function getEnterpriseManagerBridge(args: GetEnterpriseManagerBridgeArgs, opts?: pulumi.InvokeOptions): Promise<GetEnterpriseManagerBridgeResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:opsi/getEnterpriseManagerBridge:getEnterpriseManagerBridge", {
        "enterpriseManagerBridgeId": args.enterpriseManagerBridgeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getEnterpriseManagerBridge.
 */
export interface GetEnterpriseManagerBridgeArgs {
    /**
     * Unique Enterprise Manager bridge identifier
     */
    enterpriseManagerBridgeId: string;
}

/**
 * A collection of values returned by getEnterpriseManagerBridge.
 */
export interface GetEnterpriseManagerBridgeResult {
    /**
     * Compartment identifier of the Enterprise Manager bridge
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Description of Enterprise Manager Bridge
     */
    readonly description: string;
    /**
     * User-friedly name of Enterprise Manager Bridge that does not have to be unique.
     */
    readonly displayName: string;
    readonly enterpriseManagerBridgeId: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * Enterprise Manager bridge identifier
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * Object Storage Bucket Name
     */
    readonly objectStorageBucketName: string;
    /**
     * A message describing status of the object storage bucket of this resource. For example, it can be used to provide actionable information about the permission and content validity of the bucket.
     */
    readonly objectStorageBucketStatusDetails: string;
    /**
     * Object Storage Namespace Name
     */
    readonly objectStorageNamespaceName: string;
    /**
     * The current state of the Enterprise Manager bridge.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time the the Enterprise Manager bridge was first created. An RFC3339 formatted datetime string
     */
    readonly timeCreated: string;
    /**
     * The time the Enterprise Manager bridge was updated. An RFC3339 formatted datetime string
     */
    readonly timeUpdated: string;
}
