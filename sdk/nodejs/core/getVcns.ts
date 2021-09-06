// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Vcns in Oracle Cloud Infrastructure Core service.
 *
 * Lists the virtual cloud networks (VCNs) in the specified compartment.
 *
 * ## Supported Aliases
 *
 * * `ociCoreVirtualNetworks`
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVcns = oci.core.getVcns({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.vcn_display_name,
 *     state: _var.vcn_state,
 * });
 * ```
 */
export function getVcns(args: GetVcnsArgs, opts?: pulumi.InvokeOptions): Promise<GetVcnsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:core/getVcns:getVcns", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getVcns.
 */
export interface GetVcnsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.core.GetVcnsFilter[];
    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: string;
}

/**
 * A collection of values returned by getVcns.
 */
export interface GetVcnsResult {
    /**
     * The OCID of the compartment containing the VCN.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.core.GetVcnsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The VCN's current state.
     */
    readonly state?: string;
    /**
     * The list of virtual_networks.
     */
    readonly virtualNetworks: outputs.core.GetVcnsVirtualNetwork[];
}
