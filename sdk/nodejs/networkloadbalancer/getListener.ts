// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Listener resource in Oracle Cloud Infrastructure Network Load Balancer service.
 *
 * Retrieves listener properties associated with a given network load balancer and listener name.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testListener = oci.networkloadbalancer.getListener({
 *     listenerName: oci_network_load_balancer_listener.test_listener.name,
 *     networkLoadBalancerId: oci_network_load_balancer_network_load_balancer.test_network_load_balancer.id,
 * });
 * ```
 */
export function getListener(args: GetListenerArgs, opts?: pulumi.InvokeOptions): Promise<GetListenerResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:networkloadbalancer/getListener:getListener", {
        "listenerName": args.listenerName,
        "networkLoadBalancerId": args.networkLoadBalancerId,
    }, opts);
}

/**
 * A collection of arguments for invoking getListener.
 */
export interface GetListenerArgs {
    /**
     * The name of the listener to get.  Example: `exampleListener`
     */
    listenerName: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     */
    networkLoadBalancerId: string;
}

/**
 * A collection of values returned by getListener.
 */
export interface GetListenerResult {
    /**
     * The name of the associated backend set.  Example: `exampleBackendSet`
     */
    readonly defaultBackendSetName: string;
    readonly id: string;
    readonly listenerName: string;
    /**
     * A friendly name for the listener. It must be unique and it cannot be changed.  Example: `exampleListener`
     */
    readonly name: string;
    readonly networkLoadBalancerId: string;
    /**
     * The communication port for the listener.  Example: `80`
     */
    readonly port: number;
    /**
     * The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). To get a list of valid protocols, use the [ListNetworkLoadBalancersProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/NetworkLoadBalancer/20200501/networkLoadBalancerProtocol/ListNetworkLoadBalancersProtocols) operation.  Example: `TCP`
     */
    readonly protocol: string;
}
