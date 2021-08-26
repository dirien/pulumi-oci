// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Configuration resource in Oracle Cloud Infrastructure Metering Computation service.
 *
 * Returns the configurations list for the UI drop-down list.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testConfiguration = oci.meteringcomputation.getConfiguration({
 *     tenantId: oci_metering_computation_tenant.test_tenant.id,
 * });
 * ```
 */
export function getConfiguration(args: GetConfigurationArgs, opts?: pulumi.InvokeOptions): Promise<GetConfigurationResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:meteringcomputation/getConfiguration:getConfiguration", {
        "tenantId": args.tenantId,
    }, opts);
}

/**
 * A collection of arguments for invoking getConfiguration.
 */
export interface GetConfigurationArgs {
    /**
     * tenant id
     */
    tenantId: string;
}

/**
 * A collection of values returned by getConfiguration.
 */
export interface GetConfigurationResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of available configurations.
     */
    readonly items: outputs.meteringcomputation.GetConfigurationItem[];
    readonly tenantId: string;
}