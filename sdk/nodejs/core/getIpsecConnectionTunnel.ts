// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Ip Sec Connection Tunnel resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets the specified IPSec connection's specified tunnel basic information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testIpSecConnectionTunnel = oci.core.getIpsecConnectionTunnel({
 *     ipsecId: oci_core_ipsec.test_ipsec.id,
 *     tunnelId: data.oci_core_ipsec_connection_tunnels.test_ip_sec_connection_tunnels.ip_sec_connection_tunnels[0].id,
 * });
 * ```
 */
export function getIpsecConnectionTunnel(args: GetIpsecConnectionTunnelArgs, opts?: pulumi.InvokeOptions): Promise<GetIpsecConnectionTunnelResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:core/getIpsecConnectionTunnel:getIpsecConnectionTunnel", {
        "ipsecId": args.ipsecId,
        "tunnelId": args.tunnelId,
    }, opts);
}

/**
 * A collection of arguments for invoking getIpsecConnectionTunnel.
 */
export interface GetIpsecConnectionTunnelArgs {
    /**
     * The OCID of the IPSec connection.
     */
    ipsecId: string;
    /**
     * The OCID of the IPSec connection's tunnel.
     */
    tunnelId: string;
}

/**
 * A collection of values returned by getIpsecConnectionTunnel.
 */
export interface GetIpsecConnectionTunnelResult {
    /**
     * Information needed to establish a BGP Session on an interface.
     */
    readonly bgpSessionInfos: outputs.core.GetIpsecConnectionTunnelBgpSessionInfo[];
    /**
     * The OCID of the compartment containing the tunnel.
     */
    readonly compartmentId: string;
    /**
     * The IP address of Cpe headend.  Example: `129.146.17.50`
     */
    readonly cpeIp: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Configuration information used by the encryption domain policy.
     */
    readonly encryptionDomainConfig: outputs.core.GetIpsecConnectionTunnelEncryptionDomainConfig;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Internet Key Exchange protocol version.
     */
    readonly ikeVersion: string;
    readonly ipsecId: string;
    /**
     * the routing strategy used for this tunnel, either static route or BGP dynamic routing
     */
    readonly routing: string;
    /**
     * The IPSec connection's tunnel's lifecycle state.
     */
    readonly state: string;
    /**
     * The tunnel's current state.
     */
    readonly status: string;
    /**
     * The date and time the IPSec connection tunnel was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
    /**
     * When the status of the tunnel last changed, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeStatusUpdated: string;
    readonly tunnelId: string;
    /**
     * The IP address of Oracle's VPN headend.  Example: `129.146.17.50`
     */
    readonly vpnIp: string;
}
