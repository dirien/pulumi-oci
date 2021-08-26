// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Replication Sources in Oracle Cloud Infrastructure Object Storage service.
 *
 * List the replication sources of a destination bucket.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testReplicationSources = oci.objectstorage.getReplicationSources({
 *     bucket: _var.replication_source_bucket,
 *     namespace: _var.replication_source_namespace,
 * });
 * ```
 */
export function getReplicationSources(args: GetReplicationSourcesArgs, opts?: pulumi.InvokeOptions): Promise<GetReplicationSourcesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:objectstorage/getReplicationSources:getReplicationSources", {
        "bucket": args.bucket,
        "filters": args.filters,
        "namespace": args.namespace,
    }, opts);
}

/**
 * A collection of arguments for invoking getReplicationSources.
 */
export interface GetReplicationSourcesArgs {
    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     */
    bucket: string;
    filters?: inputs.objectstorage.GetReplicationSourcesFilter[];
    /**
     * The Object Storage namespace used for the request.
     */
    namespace: string;
}

/**
 * A collection of values returned by getReplicationSources.
 */
export interface GetReplicationSourcesResult {
    readonly bucket: string;
    readonly filters?: outputs.objectstorage.GetReplicationSourcesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly namespace: string;
    /**
     * The list of replication_sources.
     */
    readonly replicationSources: outputs.objectstorage.GetReplicationSourcesReplicationSource[];
}
