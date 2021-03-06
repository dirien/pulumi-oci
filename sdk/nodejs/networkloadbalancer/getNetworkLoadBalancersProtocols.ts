// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Network Load Balancers Protocols in Oracle Cloud Infrastructure Network Load Balancer service.
 *
 * Lists all supported traffic protocols.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNetworkLoadBalancersProtocols = pulumi.output(oci.networkloadbalancer.getNetworkLoadBalancersProtocols());
 * ```
 */
export function getNetworkLoadBalancersProtocols(args?: GetNetworkLoadBalancersProtocolsArgs, opts?: pulumi.InvokeOptions): Promise<GetNetworkLoadBalancersProtocolsResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:networkloadbalancer/getNetworkLoadBalancersProtocols:getNetworkLoadBalancersProtocols", {
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getNetworkLoadBalancersProtocols.
 */
export interface GetNetworkLoadBalancersProtocolsArgs {
    filters?: inputs.networkloadbalancer.GetNetworkLoadBalancersProtocolsFilter[];
}

/**
 * A collection of values returned by getNetworkLoadBalancersProtocols.
 */
export interface GetNetworkLoadBalancersProtocolsResult {
    readonly filters?: outputs.networkloadbalancer.GetNetworkLoadBalancersProtocolsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of network_load_balancers_protocol_collection.
     */
    readonly networkLoadBalancersProtocolCollections: outputs.networkloadbalancer.GetNetworkLoadBalancersProtocolsNetworkLoadBalancersProtocolCollection[];
}
