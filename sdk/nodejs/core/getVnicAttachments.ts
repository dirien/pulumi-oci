// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Vnic Attachments in Oracle Cloud Infrastructure Core service.
 *
 * Lists the VNIC attachments in the specified compartment. A VNIC attachment
 * resides in the same compartment as the attached instance. The list can be
 * filtered by instance, VNIC, or availability domain.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVnicAttachments = oci.core.getVnicAttachments({
 *     compartmentId: _var.compartment_id,
 *     availabilityDomain: _var.vnic_attachment_availability_domain,
 *     instanceId: oci_core_instance.test_instance.id,
 *     vnicId: oci_core_vnic.test_vnic.id,
 * });
 * ```
 */
export function getVnicAttachments(args: GetVnicAttachmentsArgs, opts?: pulumi.InvokeOptions): Promise<GetVnicAttachmentsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:core/getVnicAttachments:getVnicAttachments", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "instanceId": args.instanceId,
        "vnicId": args.vnicId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVnicAttachments.
 */
export interface GetVnicAttachmentsArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    filters?: inputs.core.GetVnicAttachmentsFilter[];
    /**
     * The OCID of the instance.
     */
    instanceId?: string;
    /**
     * The OCID of the VNIC.
     */
    vnicId?: string;
}

/**
 * A collection of values returned by getVnicAttachments.
 */
export interface GetVnicAttachmentsResult {
    /**
     * The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     */
    readonly availabilityDomain?: string;
    /**
     * The OCID of the compartment the VNIC attachment is in, which is the same compartment the instance is in.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.core.GetVnicAttachmentsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The OCID of the instance.
     */
    readonly instanceId?: string;
    /**
     * The list of vnic_attachments.
     */
    readonly vnicAttachments: outputs.core.GetVnicAttachmentsVnicAttachment[];
    /**
     * The OCID of the VNIC. Available after the attachment process is complete.
     */
    readonly vnicId?: string;
}
