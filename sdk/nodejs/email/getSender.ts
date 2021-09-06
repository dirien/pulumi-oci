// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Sender resource in Oracle Cloud Infrastructure Email service.
 *
 * Gets an approved sender for a given `senderId`.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSender = oci.email.getSender({
 *     senderId: oci_email_sender.test_sender.id,
 * });
 * ```
 */
export function getSender(args: GetSenderArgs, opts?: pulumi.InvokeOptions): Promise<GetSenderResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:email/getSender:getSender", {
        "senderId": args.senderId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSender.
 */
export interface GetSenderArgs {
    /**
     * The unique OCID of the sender.
     */
    senderId: string;
}

/**
 * A collection of values returned by getSender.
 */
export interface GetSenderResult {
    /**
     * The OCID for the compartment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * The email address of the sender.
     */
    readonly emailAddress: string;
    /**
     * The email domain used to assert responsibility for emails sent from this sender.
     */
    readonly emailDomainId: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The unique OCID of the sender.
     */
    readonly id: string;
    /**
     * Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
     */
    readonly isSpf: boolean;
    readonly senderId: string;
    /**
     * The current status of the approved sender.
     */
    readonly state: string;
    /**
     * The date and time the approved sender was added in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    readonly timeCreated: string;
}
