// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Certificates in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
 *
 * Gets a list of SSL certificates that can be used in a WAAS policy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCertificates = oci.waas.getCertificates({
 *     compartmentId: _var.compartment_id,
 *     displayNames: _var.certificate_display_names,
 *     ids: _var.certificate_ids,
 *     states: _var.certificate_states,
 *     timeCreatedGreaterThanOrEqualTo: _var.certificate_time_created_greater_than_or_equal_to,
 *     timeCreatedLessThan: _var.certificate_time_created_less_than,
 * });
 * ```
 */
export function getCertificates(args: GetCertificatesArgs, opts?: pulumi.InvokeOptions): Promise<GetCertificatesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:waas/getCertificates:getCertificates", {
        "compartmentId": args.compartmentId,
        "displayNames": args.displayNames,
        "filters": args.filters,
        "ids": args.ids,
        "states": args.states,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getCertificates.
 */
export interface GetCertificatesArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
     */
    compartmentId: string;
    /**
     * Filter certificates using a list of display names.
     */
    displayNames?: string[];
    filters?: inputs.waas.GetCertificatesFilter[];
    /**
     * Filter certificates using a list of certificates OCIDs.
     */
    ids?: string[];
    /**
     * Filter certificates using a list of lifecycle states.
     */
    states?: string[];
    /**
     * A filter that matches certificates created on or after the specified date-time.
     */
    timeCreatedGreaterThanOrEqualTo?: string;
    /**
     * A filter that matches certificates created before the specified date-time.
     */
    timeCreatedLessThan?: string;
}

/**
 * A collection of values returned by getCertificates.
 */
export interface GetCertificatesResult {
    /**
     * The list of certificates.
     */
    readonly certificates: outputs.waas.GetCertificatesCertificate[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SSL certificate's compartment.
     */
    readonly compartmentId: string;
    readonly displayNames?: string[];
    readonly filters?: outputs.waas.GetCertificatesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly ids?: string[];
    readonly states?: string[];
    readonly timeCreatedGreaterThanOrEqualTo?: string;
    readonly timeCreatedLessThan?: string;
}
