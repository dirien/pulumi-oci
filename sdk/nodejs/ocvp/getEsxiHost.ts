// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Esxi Host resource in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
 *
 * Gets the specified ESXi host's information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testEsxiHost = oci.ocvp.getEsxiHost({
 *     esxiHostId: oci_ocvp_esxi_host.test_esxi_host.id,
 * });
 * ```
 */
export function getEsxiHost(args: GetEsxiHostArgs, opts?: pulumi.InvokeOptions): Promise<GetEsxiHostResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:ocvp/getEsxiHost:getEsxiHost", {
        "esxiHostId": args.esxiHostId,
    }, opts);
}

/**
 * A collection of arguments for invoking getEsxiHost.
 */
export interface GetEsxiHostArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ESXi host.
     */
    esxiHostId: string;
}

/**
 * A collection of values returned by getEsxiHost.
 */
export interface GetEsxiHostResult {
    /**
     * Current billing cycle end date. If nextSku is different from existing SKU, then we switch to newSKu after this contractEndDate Example: `2016-08-25T21:10:29.600Z`
     */
    readonly billingContractEndDate: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the SDDC.
     */
    readonly compartmentId: string;
    /**
     * In terms of implementation, an ESXi host is a Compute instance that is configured with the chosen bundle of VMware software. The `computeInstanceId` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of that Compute instance.
     */
    readonly computeInstanceId: string;
    /**
     * Billing option selected during SDDC creation. Oracle Cloud Infrastructure VMware Solution supports the following billing interval SKUs: HOUR, MONTH, ONE_YEAR, and THREE_YEARS. [ListSupportedSkus](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedSkuSummary/ListSupportedSkus).
     */
    readonly currentSku: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A descriptive name for the ESXi host. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName: string;
    readonly esxiHostId: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ESXi host.
     */
    readonly id: string;
    /**
     * Billing option to switch to once existing billing cycle ends. [ListSupportedSkus](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedSkuSummary/ListSupportedSkus).
     */
    readonly nextSku: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC that the ESXi host belongs to.
     */
    readonly sddcId: string;
    /**
     * The current state of the ESXi host.
     */
    readonly state: string;
    /**
     * The date and time the ESXi host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
    /**
     * The date and time the ESXi host was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeUpdated: string;
}