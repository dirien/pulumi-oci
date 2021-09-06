// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Object resource in Oracle Cloud Infrastructure Object Storage service.
 *
 * Gets the metadata and body of an object.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testObject = oci.objectstorage.getObject({
 *     bucket: _var.object_bucket,
 *     namespace: _var.object_namespace,
 *     object: _var.object_object,
 *     httpResponseCacheControl: _var.object_http_response_cache_control,
 *     httpResponseContentDisposition: _var.object_http_response_content_disposition,
 *     httpResponseContentEncoding: _var.object_http_response_content_encoding,
 *     httpResponseContentLanguage: _var.object_http_response_content_language,
 *     httpResponseContentType: _var.object_http_response_content_type,
 *     httpResponseExpires: _var.object_http_response_expires,
 *     versionId: oci_objectstorage_version.test_version.id,
 * });
 * ```
 */
export function getObject(args: GetObjectArgs, opts?: pulumi.InvokeOptions): Promise<GetObjectResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:objectstorage/getObject:getObject", {
        "base64EncodeContent": args.base64EncodeContent,
        "bucket": args.bucket,
        "contentLengthLimit": args.contentLengthLimit,
        "httpResponseCacheControl": args.httpResponseCacheControl,
        "httpResponseContentDisposition": args.httpResponseContentDisposition,
        "httpResponseContentEncoding": args.httpResponseContentEncoding,
        "httpResponseContentLanguage": args.httpResponseContentLanguage,
        "httpResponseContentType": args.httpResponseContentType,
        "httpResponseExpires": args.httpResponseExpires,
        "namespace": args.namespace,
        "object": args.object,
        "versionId": args.versionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getObject.
 */
export interface GetObjectArgs {
    base64EncodeContent?: boolean;
    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     */
    bucket: string;
    /**
     * The limit of the content length of the object body to download from the object store. The default is 1Mb.
     */
    contentLengthLimit?: number;
    /**
     * Specify this query parameter to override the Cache-Control response header in the GetObject response.
     */
    httpResponseCacheControl?: string;
    /**
     * Specify this query parameter to override the value of the Content-Disposition response header in the GetObject response.
     */
    httpResponseContentDisposition?: string;
    /**
     * Specify this query parameter to override the Content-Encoding response header in the GetObject response.
     */
    httpResponseContentEncoding?: string;
    /**
     * Specify this query parameter to override the Content-Language response header in the GetObject response.
     */
    httpResponseContentLanguage?: string;
    /**
     * Specify this query parameter to override the Content-Type response header in the GetObject response.
     */
    httpResponseContentType?: string;
    /**
     * Specify this query parameter to override the Expires response header in the GetObject response.
     */
    httpResponseExpires?: string;
    /**
     * The Object Storage namespace used for the request.
     */
    namespace: string;
    /**
     * The name of the object. Avoid entering confidential information. Example: `test/object1.log`
     */
    object: string;
    /**
     * VersionId used to identify a particular version of the object
     */
    versionId?: string;
}

/**
 * A collection of values returned by getObject.
 */
export interface GetObjectResult {
    readonly base64EncodeContent?: boolean;
    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     */
    readonly bucket: string;
    readonly cacheControl: string;
    /**
     * The object to upload to the object store.
     */
    readonly content: string;
    readonly contentDisposition: string;
    /**
     * The content encoding of the object.
     */
    readonly contentEncoding: string;
    /**
     * The content language of the object.
     */
    readonly contentLanguage: string;
    /**
     * The content length of the body.
     */
    readonly contentLength: string;
    readonly contentLengthLimit?: number;
    /**
     * The base-64 encoded MD5 hash of the body.
     */
    readonly contentMd5: string;
    /**
     * The content type of the object.  Defaults to 'application/octet-stream' if not overridden during the PutObject call.
     */
    readonly contentType: string;
    readonly httpResponseCacheControl?: string;
    readonly httpResponseContentDisposition?: string;
    readonly httpResponseContentEncoding?: string;
    readonly httpResponseContentLanguage?: string;
    readonly httpResponseContentType?: string;
    readonly httpResponseExpires?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Optional user-defined metadata key and value. Note: Metadata keys are case-insensitive and all returned keys will be lower case.
     */
    readonly metadata: {[key: string]: any};
    /**
     * The top-level namespace used for the request.
     */
    readonly namespace: string;
    /**
     * The name of the object. Avoid entering confidential information. Example: `test/object1.log`
     */
    readonly object: string;
    /**
     * The storage tier that the object is stored in.
     */
    readonly storageTier: string;
    readonly versionId: string;
}
