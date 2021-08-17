// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "./types";
import * as utilities from "./utilities";

/**
 * This data source provides the list of Availability Domains in Oracle Cloud Infrastructure Identity service.
 *
 * Lists the availability domains in your tenancy. Specify the OCID of either the tenancy or another
 * of your compartments as the value for the compartment ID (remember that the tenancy is simply the root compartment).
 * See [Where to Get the Tenancy's OCID and User's OCID](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm#five).
 * Note that the order of the results returned can change if availability domains are added or removed; therefore, do not
 * create a dependency on the list order.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAvailabilityDomains = oci.GetIdentityAvailabilityDomains({
 *     compartmentId: _var.tenancy_ocid,
 * });
 * ```
 */
export function getIdentityAvailabilityDomains(args: GetIdentityAvailabilityDomainsArgs, opts?: pulumi.InvokeOptions): Promise<GetIdentityAvailabilityDomainsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:index/getIdentityAvailabilityDomains:GetIdentityAvailabilityDomains", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking GetIdentityAvailabilityDomains.
 */
export interface GetIdentityAvailabilityDomainsArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId: string;
    filters?: inputs.GetIdentityAvailabilityDomainsFilter[];
}

/**
 * A collection of values returned by GetIdentityAvailabilityDomains.
 */
export interface GetIdentityAvailabilityDomainsResult {
    /**
     * The list of availability_domains.
     */
    readonly availabilityDomains: outputs.GetIdentityAvailabilityDomainsAvailabilityDomain[];
    /**
     * The OCID of the tenancy.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.GetIdentityAvailabilityDomainsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}