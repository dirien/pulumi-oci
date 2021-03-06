// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Compute Image Capability Schemas in Oracle Cloud Infrastructure Core service.
 *
 * Lists Compute Image Capability Schema in the specified compartment. You can also query by a specific imageId.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testComputeImageCapabilitySchemas = oci.core.getComputeImageCapabilitySchemas({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.compute_image_capability_schema_display_name,
 *     imageId: oci_core_image.test_image.id,
 * });
 * ```
 */
export function getComputeImageCapabilitySchemas(args?: GetComputeImageCapabilitySchemasArgs, opts?: pulumi.InvokeOptions): Promise<GetComputeImageCapabilitySchemasResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:core/getComputeImageCapabilitySchemas:getComputeImageCapabilitySchemas", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "imageId": args.imageId,
    }, opts);
}

/**
 * A collection of arguments for invoking getComputeImageCapabilitySchemas.
 */
export interface GetComputeImageCapabilitySchemasArgs {
    /**
     * A filter to return only resources that match the given compartment OCID exactly.
     */
    compartmentId?: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.core.GetComputeImageCapabilitySchemasFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an image.
     */
    imageId?: string;
}

/**
 * A collection of values returned by getComputeImageCapabilitySchemas.
 */
export interface GetComputeImageCapabilitySchemasResult {
    /**
     * The OCID of the compartment containing the compute global image capability schema
     */
    readonly compartmentId?: string;
    /**
     * The list of compute_image_capability_schemas.
     */
    readonly computeImageCapabilitySchemas: outputs.core.GetComputeImageCapabilitySchemasComputeImageCapabilitySchema[];
    /**
     * A user-friendly name for the compute global image capability schema
     */
    readonly displayName?: string;
    readonly filters?: outputs.core.GetComputeImageCapabilitySchemasFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The OCID of the image associated with this compute image capability schema
     */
    readonly imageId?: string;
}
