// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Stream Pools in Oracle Cloud Infrastructure Streaming service.
 *
 * List the stream pools for a given compartment ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testStreamPools = oci.streaming.getStreamPools({
 *     compartmentId: _var.compartment_id,
 *     id: _var.stream_pool_id,
 *     name: _var.stream_pool_name,
 *     state: _var.stream_pool_state,
 * });
 * ```
 */
export function getStreamPools(args: GetStreamPoolsArgs, opts?: pulumi.InvokeOptions): Promise<GetStreamPoolsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:streaming/getStreamPools:getStreamPools", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "id": args.id,
        "name": args.name,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getStreamPools.
 */
export interface GetStreamPoolsArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: string;
    filters?: inputs.streaming.GetStreamPoolsFilter[];
    /**
     * A filter to return only resources that match the given ID exactly.
     */
    id?: string;
    /**
     * A filter to return only resources that match the given name exactly.
     */
    name?: string;
    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: string;
}

/**
 * A collection of values returned by getStreamPools.
 */
export interface GetStreamPoolsResult {
    /**
     * Compartment OCID that the pool belongs to.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.streaming.GetStreamPoolsFilter[];
    /**
     * The OCID of the stream pool.
     */
    readonly id?: string;
    /**
     * The name of the stream pool.
     */
    readonly name?: string;
    /**
     * The current state of the stream pool.
     */
    readonly state?: string;
    /**
     * The list of stream_pools.
     */
    readonly streamPools: outputs.streaming.GetStreamPoolsStreamPool[];
}
