// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Software Source resource in Oracle Cloud Infrastructure OS Management service.
 *
 * Returns a specific Software Source.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSoftwareSource = oci.osmanagement.getSoftwareSource({
 *     softwareSourceId: oci_osmanagement_software_source.test_software_source.id,
 * });
 * ```
 */
export function getSoftwareSource(args: GetSoftwareSourceArgs, opts?: pulumi.InvokeOptions): Promise<GetSoftwareSourceResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:osmanagement/getSoftwareSource:getSoftwareSource", {
        "softwareSourceId": args.softwareSourceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSoftwareSource.
 */
export interface GetSoftwareSourceArgs {
    /**
     * The OCID of the software source.
     */
    softwareSourceId: string;
}

/**
 * A collection of values returned by getSoftwareSource.
 */
export interface GetSoftwareSourceResult {
    /**
     * The architecture type supported by the Software Source
     */
    readonly archType: string;
    /**
     * list of the Managed Instances associated with this Software Sources
     */
    readonly associatedManagedInstances: outputs.osmanagement.GetSoftwareSourceAssociatedManagedInstance[];
    /**
     * The yum repository checksum type used by this software source
     */
    readonly checksumType: string;
    /**
     * OCID for the Compartment
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Information specified by the user about the software source
     */
    readonly description: string;
    /**
     * User friendly name for the software source
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * Fingerprint of the GPG key for this software source
     */
    readonly gpgKeyFingerprint: string;
    /**
     * ID of the GPG key for this software source
     */
    readonly gpgKeyId: string;
    /**
     * URL of the GPG key for this software source
     */
    readonly gpgKeyUrl: string;
    /**
     * OCID for the Software Source
     */
    readonly id: string;
    /**
     * Email address of the person maintaining this software source
     */
    readonly maintainerEmail: string;
    /**
     * Name of the person maintaining this software source
     */
    readonly maintainerName: string;
    /**
     * Phone number of the person maintaining this software source
     */
    readonly maintainerPhone: string;
    /**
     * Number of packages
     */
    readonly packages: number;
    /**
     * OCID for the parent software source, if there is one
     */
    readonly parentId: string;
    /**
     * Display name the parent software source, if there is one
     */
    readonly parentName: string;
    /**
     * Type of the Software Source
     */
    readonly repoType: string;
    readonly softwareSourceId: string;
    /**
     * The current state of the Software Source.
     */
    readonly state: string;
    /**
     * status of the software source.
     */
    readonly status: string;
    /**
     * URL for the repostiory
     */
    readonly url: string;
}
