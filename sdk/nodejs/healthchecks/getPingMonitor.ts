// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Ping Monitor resource in Oracle Cloud Infrastructure Health Checks service.
 *
 * Gets the configuration for the specified ping monitor.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPingMonitor = oci.healthchecks.getPingMonitor({
 *     monitorId: oci_apm_synthetics_monitor.test_monitor.id,
 * });
 * ```
 */
export function getPingMonitor(args: GetPingMonitorArgs, opts?: pulumi.InvokeOptions): Promise<GetPingMonitorResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:healthchecks/getPingMonitor:getPingMonitor", {
        "monitorId": args.monitorId,
    }, opts);
}

/**
 * A collection of arguments for invoking getPingMonitor.
 */
export interface GetPingMonitorArgs {
    /**
     * The OCID of a monitor.
     */
    monitorId: string;
}

/**
 * A collection of values returned by getPingMonitor.
 */
export interface GetPingMonitorResult {
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A user-friendly and mutable name suitable for display in a user interface.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The region where updates must be made and where results must be fetched from.
     */
    readonly homeRegion: string;
    /**
     * The OCID of the resource.
     */
    readonly id: string;
    /**
     * The monitor interval in seconds. Valid values: 10, 30, and 60.
     */
    readonly intervalInSeconds: number;
    /**
     * Enables or disables the monitor. Set to 'true' to launch monitoring.
     */
    readonly isEnabled: boolean;
    readonly monitorId: string;
    /**
     * The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
     */
    readonly port: number;
    /**
     * The protocols for ping probes.
     */
    readonly protocol: string;
    /**
     * A URL for fetching the probe results.
     */
    readonly resultsUrl: string;
    /**
     * A list of targets (hostnames or IP addresses) of the probe.
     */
    readonly targets: string[];
    /**
     * The RFC 3339-formatted creation date and time of the probe.
     */
    readonly timeCreated: string;
    /**
     * The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
     */
    readonly timeoutInSeconds: number;
    /**
     * A list of names of vantage points from which to execute the probe.
     */
    readonly vantagePointNames: string[];
}
