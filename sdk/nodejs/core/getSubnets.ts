// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Subnets in Oracle Cloud Infrastructure Core service.
 *
 * Lists the subnets in the specified VCN and the specified compartment.
 * If the VCN ID is not provided, then the list includes the subnets from all VCNs in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSubnets = oci.core.getSubnets({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.subnet_display_name,
 *     state: _var.subnet_state,
 *     vcnId: oci_core_vcn.test_vcn.id,
 * });
 * ```
 */
export function getSubnets(args: GetSubnetsArgs, opts?: pulumi.InvokeOptions): Promise<GetSubnetsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:core/getSubnets:getSubnets", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
        "vcnId": args.vcnId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSubnets.
 */
export interface GetSubnetsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.core.GetSubnetsFilter[];
    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     */
    vcnId?: string;
}

/**
 * A collection of values returned by getSubnets.
 */
export interface GetSubnetsResult {
    /**
     * The OCID of the compartment containing the subnet.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.core.GetSubnetsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The subnet's current state.
     */
    readonly state?: string;
    /**
     * The list of subnets.
     */
    readonly subnets: outputs.core.GetSubnetsSubnet[];
    /**
     * The OCID of the VCN the subnet is in.
     */
    readonly vcnId?: string;
}
