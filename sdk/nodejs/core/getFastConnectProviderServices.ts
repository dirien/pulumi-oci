// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Fast Connect Provider Services in Oracle Cloud Infrastructure Core service.
 *
 * Lists the service offerings from supported providers. You need this
 * information so you can specify your desired provider and service
 * offering when you create a virtual circuit.
 *
 * For the compartment ID, provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of your tenancy (the root compartment).
 *
 * For more information, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFastConnectProviderServices = oci.core.getFastConnectProviderServices({
 *     compartmentId: _var.compartment_id,
 * });
 * ```
 */
export function getFastConnectProviderServices(args: GetFastConnectProviderServicesArgs, opts?: pulumi.InvokeOptions): Promise<GetFastConnectProviderServicesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:core/getFastConnectProviderServices:getFastConnectProviderServices", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getFastConnectProviderServices.
 */
export interface GetFastConnectProviderServicesArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    filters?: inputs.core.GetFastConnectProviderServicesFilter[];
}

/**
 * A collection of values returned by getFastConnectProviderServices.
 */
export interface GetFastConnectProviderServicesResult {
    readonly compartmentId: string;
    /**
     * The list of fast_connect_provider_services.
     */
    readonly fastConnectProviderServices: outputs.core.GetFastConnectProviderServicesFastConnectProviderService[];
    readonly filters?: outputs.core.GetFastConnectProviderServicesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
