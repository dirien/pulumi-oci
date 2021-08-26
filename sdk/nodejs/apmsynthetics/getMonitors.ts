// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Monitors in Oracle Cloud Infrastructure Apm Synthetics service.
 *
 * Returns a list of monitors.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMonitors = oci.apmsynthetics.getMonitors({
 *     apmDomainId: oci_apm_synthetics_apm_domain.test_apm_domain.id,
 *     displayName: _var.monitor_display_name,
 *     monitorType: _var.monitor_monitor_type,
 *     scriptId: oci_apm_synthetics_script.test_script.id,
 *     status: _var.monitor_status,
 * });
 * ```
 */
export function getMonitors(args: GetMonitorsArgs, opts?: pulumi.InvokeOptions): Promise<GetMonitorsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:apmsynthetics/getMonitors:getMonitors", {
        "apmDomainId": args.apmDomainId,
        "displayName": args.displayName,
        "filters": args.filters,
        "monitorType": args.monitorType,
        "scriptId": args.scriptId,
        "status": args.status,
    }, opts);
}

/**
 * A collection of arguments for invoking getMonitors.
 */
export interface GetMonitorsArgs {
    /**
     * The APM domain ID the request is intended for.
     */
    apmDomainId: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.apmsynthetics.GetMonitorsFilter[];
    /**
     * A filter to return only monitors that match the given monitor type. Supported values are SCRIPTED_BROWSER, BROWSER, SCRIPTED_REST and REST.
     */
    monitorType?: string;
    /**
     * A filter to return only monitors using scriptId.
     */
    scriptId?: string;
    /**
     * A filter to return only monitors that match the status given.
     */
    status?: string;
}

/**
 * A collection of values returned by getMonitors.
 */
export interface GetMonitorsResult {
    readonly apmDomainId: string;
    /**
     * Unique name that can be edited. The name should not contain any confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.apmsynthetics.GetMonitorsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of monitor_collection.
     */
    readonly monitorCollections: outputs.apmsynthetics.GetMonitorsMonitorCollection[];
    /**
     * Type of the monitor.
     */
    readonly monitorType?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the script. scriptId is mandatory for creation of SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null.
     */
    readonly scriptId?: string;
    /**
     * Enables or disables the monitor.
     */
    readonly status?: string;
}