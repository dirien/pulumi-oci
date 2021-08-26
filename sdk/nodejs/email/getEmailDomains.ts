// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Email Domains in Oracle Cloud Infrastructure Email service.
 *
 * Lists email domains in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testEmailDomains = oci.email.getEmailDomains({
 *     compartmentId: _var.compartment_id,
 *     id: _var.email_domain_id,
 *     name: _var.email_domain_name,
 *     state: _var.email_domain_state,
 * });
 * ```
 */
export function getEmailDomains(args: GetEmailDomainsArgs, opts?: pulumi.InvokeOptions): Promise<GetEmailDomainsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:email/getEmailDomains:getEmailDomains", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "id": args.id,
        "name": args.name,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getEmailDomains.
 */
export interface GetEmailDomainsArgs {
    /**
     * The OCID for the compartment.
     */
    compartmentId: string;
    filters?: inputs.email.GetEmailDomainsFilter[];
    /**
     * A filter to only return resources that match the given id exactly.
     */
    id?: string;
    /**
     * A filter to only return resources that match the given name exactly.
     */
    name?: string;
    /**
     * Filter returned list by specified lifecycle state. This parameter is case-insensitive.
     */
    state?: string;
}

/**
 * A collection of values returned by getEmailDomains.
 */
export interface GetEmailDomainsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains this email domain.
     */
    readonly compartmentId: string;
    /**
     * The list of email_domain_collection.
     */
    readonly emailDomainCollections: outputs.email.GetEmailDomainsEmailDomainCollection[];
    readonly filters?: outputs.email.GetEmailDomainsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain.
     */
    readonly id?: string;
    /**
     * The name of the email domain in the Internet Domain Name System (DNS).  Example: `example.net`
     */
    readonly name?: string;
    /**
     * The current state of the email domain.
     */
    readonly state?: string;
}