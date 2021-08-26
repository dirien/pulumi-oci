// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Replication Policies in Oracle Cloud Infrastructure Object Storage service.
 *
 * List the replication policies associated with a bucket.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testReplicationPolicies = oci.objectstorage.getReplicationPolicies({
 *     bucket: _var.replication_policy_bucket,
 *     namespace: _var.replication_policy_namespace,
 * });
 * ```
 */
export function getReplicationPolicies(args: GetReplicationPoliciesArgs, opts?: pulumi.InvokeOptions): Promise<GetReplicationPoliciesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:objectstorage/getReplicationPolicies:getReplicationPolicies", {
        "bucket": args.bucket,
        "filters": args.filters,
        "namespace": args.namespace,
    }, opts);
}

/**
 * A collection of arguments for invoking getReplicationPolicies.
 */
export interface GetReplicationPoliciesArgs {
    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     */
    bucket: string;
    filters?: inputs.objectstorage.GetReplicationPoliciesFilter[];
    /**
     * The Object Storage namespace used for the request.
     */
    namespace: string;
}

/**
 * A collection of values returned by getReplicationPolicies.
 */
export interface GetReplicationPoliciesResult {
    readonly bucket: string;
    readonly filters?: outputs.objectstorage.GetReplicationPoliciesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly namespace: string;
    /**
     * The list of replication_policies.
     */
    readonly replicationPolicies: outputs.objectstorage.GetReplicationPoliciesReplicationPolicy[];
}