// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Private Applications in Oracle Cloud Infrastructure Service Catalog service.
 *
 * Lists all the private applications in a given compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPrivateApplications = oci.servicecatalog.getPrivateApplications({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.private_application_display_name,
 *     privateApplicationId: oci_service_catalog_private_application.test_private_application.id,
 * });
 * ```
 */
export function getPrivateApplications(args: GetPrivateApplicationsArgs, opts?: pulumi.InvokeOptions): Promise<GetPrivateApplicationsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:servicecatalog/getPrivateApplications:getPrivateApplications", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "privateApplicationId": args.privateApplicationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getPrivateApplications.
 */
export interface GetPrivateApplicationsArgs {
    /**
     * The unique identifier for the compartment.
     */
    compartmentId: string;
    /**
     * Exact match name filter.
     */
    displayName?: string;
    filters?: inputs.servicecatalog.GetPrivateApplicationsFilter[];
    /**
     * The unique identifier for the private application.
     */
    privateApplicationId?: string;
}

/**
 * A collection of values returned by getPrivateApplications.
 */
export interface GetPrivateApplicationsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the private application resides.
     */
    readonly compartmentId: string;
    /**
     * The name used to refer to the uploaded data.
     */
    readonly displayName?: string;
    readonly filters?: outputs.servicecatalog.GetPrivateApplicationsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of private_application_collection.
     */
    readonly privateApplicationCollections: outputs.servicecatalog.GetPrivateApplicationsPrivateApplicationCollection[];
    readonly privateApplicationId?: string;
}
