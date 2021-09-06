// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Namespace resource in Oracle Cloud Infrastructure Log Analytics service.
 *
 * This API gets the namespace details of a tenancy already onboarded in Logging Analytics Application
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespace = oci.loganalytics.getNamespace({
 *     namespace: _var.namespace_namespace,
 * });
 * ```
 */
export function getNamespace(args: GetNamespaceArgs, opts?: pulumi.InvokeOptions): Promise<GetNamespaceResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:loganalytics/getNamespace:getNamespace", {
        "namespace": args.namespace,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespace.
 */
export interface GetNamespaceArgs {
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: string;
}

/**
 * A collection of values returned by getNamespace.
 */
export interface GetNamespaceResult {
    /**
     * The is the tenancy ID
     */
    readonly compartmentId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * This indicates if the tenancy is onboarded to Logging Analytics
     */
    readonly isOnboarded: boolean;
    /**
     * This is the namespace name of a tenancy
     */
    readonly namespace: string;
}
