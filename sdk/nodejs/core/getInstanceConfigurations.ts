// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Instance Configurations in Oracle Cloud Infrastructure Core service.
 *
 * Lists the instance configurations in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInstanceConfigurations = oci.core.getInstanceConfigurations({
 *     compartmentId: _var.compartment_id,
 * });
 * ```
 */
export function getInstanceConfigurations(args: GetInstanceConfigurationsArgs, opts?: pulumi.InvokeOptions): Promise<GetInstanceConfigurationsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:core/getInstanceConfigurations:getInstanceConfigurations", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getInstanceConfigurations.
 */
export interface GetInstanceConfigurationsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    filters?: inputs.core.GetInstanceConfigurationsFilter[];
}

/**
 * A collection of values returned by getInstanceConfigurations.
 */
export interface GetInstanceConfigurationsResult {
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.core.GetInstanceConfigurationsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of instance_configurations.
     */
    readonly instanceConfigurations: outputs.core.GetInstanceConfigurationsInstanceConfiguration[];
}
