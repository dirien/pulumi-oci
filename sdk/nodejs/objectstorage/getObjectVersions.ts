// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Object Versions in Oracle Cloud Infrastructure Object Storage service.
 *
 * Lists the object versions in a bucket.
 *
 * ListObjectVersions returns an ObjectVersionCollection containing at most 1000 object versions. To paginate through
 * more object versions, use the returned `opc-next-page` value with the `page` request parameter.
 *
 * To use this and other API operations, you must be authorized in an IAM policy. If you are not authorized,
 * talk to an administrator. If you are an administrator who needs to write policies to give users access, see
 * [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testObjectVersions = oci.objectstorage.getObjectVersions({
 *     bucket: _var.object_version_bucket,
 *     namespace: _var.object_version_namespace,
 *     delimiter: _var.object_version_delimiter,
 *     end: _var.object_version_end,
 *     fields: _var.object_version_fields,
 *     prefix: _var.object_version_prefix,
 *     start: _var.object_version_start,
 *     startAfter: _var.object_version_start_after,
 * });
 * ```
 */
export function getObjectVersions(args: GetObjectVersionsArgs, opts?: pulumi.InvokeOptions): Promise<GetObjectVersionsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:objectstorage/getObjectVersions:getObjectVersions", {
        "bucket": args.bucket,
        "delimiter": args.delimiter,
        "end": args.end,
        "fields": args.fields,
        "filters": args.filters,
        "namespace": args.namespace,
        "prefix": args.prefix,
        "start": args.start,
        "startAfter": args.startAfter,
    }, opts);
}

/**
 * A collection of arguments for invoking getObjectVersions.
 */
export interface GetObjectVersionsArgs {
    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     */
    bucket: string;
    /**
     * When this parameter is set, only objects whose names do not contain the delimiter character (after an optionally specified prefix) are returned in the objects key of the response body. Scanned objects whose names contain the delimiter have the part of their name up to the first occurrence of the delimiter (including the optional prefix) returned as a set of prefixes. Note that only '/' is a supported delimiter character at this time.
     */
    delimiter?: string;
    /**
     * Object names returned by a list query must be strictly less than this parameter.
     */
    end?: string;
    /**
     * Object summary by default includes only the 'name' field. Use this parameter to also include 'size' (object size in bytes), 'etag', 'md5', 'timeCreated' (object creation date and time), 'timeModified' (object modification date and time), 'storageTier' and 'archivalState' fields. Specify the value of this parameter as a comma-separated, case-insensitive list of those field names.  For example 'name,etag,timeCreated,md5,timeModified,storageTier,archivalState'.
     */
    fields?: string;
    filters?: inputs.objectstorage.GetObjectVersionsFilter[];
    /**
     * The Object Storage namespace used for the request.
     */
    namespace: string;
    /**
     * The string to use for matching against the start of object names in a list query.
     */
    prefix?: string;
    /**
     * Object names returned by a list query must be greater or equal to this parameter.
     */
    start?: string;
    /**
     * Object names returned by a list query must be greater than this parameter.
     */
    startAfter?: string;
}

/**
 * A collection of values returned by getObjectVersions.
 */
export interface GetObjectVersionsResult {
    readonly bucket: string;
    readonly delimiter?: string;
    readonly end?: string;
    readonly fields?: string;
    readonly filters?: outputs.objectstorage.GetObjectVersionsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * An array of object version summaries.
     */
    readonly items: outputs.objectstorage.GetObjectVersionsItem[];
    readonly namespace: string;
    readonly prefix?: string;
    /**
     * Prefixes that are common to the results returned by the request if the request specified a delimiter.
     */
    readonly prefixes: string[];
    readonly start?: string;
    readonly startAfter?: string;
}
