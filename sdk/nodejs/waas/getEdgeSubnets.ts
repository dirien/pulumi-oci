// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Edge Subnets in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
 *
 * Return the list of the tenant's edge node subnets. Use these CIDR blocks to restrict incoming traffic to your origin. These subnets are owned by Oracle Cloud Infrastructure and forward traffic to customer origins. They are not associated with specific regions or compartments.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testEdgeSubnets = pulumi.output(oci.waas.getEdgeSubnets());
 * ```
 */
export function getEdgeSubnets(args?: GetEdgeSubnetsArgs, opts?: pulumi.InvokeOptions): Promise<GetEdgeSubnetsResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:waas/getEdgeSubnets:getEdgeSubnets", {
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getEdgeSubnets.
 */
export interface GetEdgeSubnetsArgs {
    filters?: inputs.waas.GetEdgeSubnetsFilter[];
}

/**
 * A collection of values returned by getEdgeSubnets.
 */
export interface GetEdgeSubnetsResult {
    /**
     * The list of edge_subnets.
     */
    readonly edgeSubnets: outputs.waas.GetEdgeSubnetsEdgeSubnet[];
    readonly filters?: outputs.waas.GetEdgeSubnetsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
