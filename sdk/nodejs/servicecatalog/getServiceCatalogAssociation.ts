// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Service Catalog Association resource in Oracle Cloud Infrastructure Service Catalog service.
 *
 * Gets detailed information about specific service catalog association.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testServiceCatalogAssociation = oci.servicecatalog.getServiceCatalogAssociation({
 *     serviceCatalogAssociationId: oci_service_catalog_service_catalog_association.test_service_catalog_association.id,
 * });
 * ```
 */
export function getServiceCatalogAssociation(args: GetServiceCatalogAssociationArgs, opts?: pulumi.InvokeOptions): Promise<GetServiceCatalogAssociationResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:servicecatalog/getServiceCatalogAssociation:getServiceCatalogAssociation", {
        "serviceCatalogAssociationId": args.serviceCatalogAssociationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getServiceCatalogAssociation.
 */
export interface GetServiceCatalogAssociationArgs {
    /**
     * The unique identifier of the service catalog association.
     */
    serviceCatalogAssociationId: string;
}

/**
 * A collection of values returned by getServiceCatalogAssociation.
 */
export interface GetServiceCatalogAssociationResult {
    /**
     * Identifier of the entity being associated with service catalog.
     */
    readonly entityId: string;
    /**
     * The type of the entity that is associated with the service catalog.
     */
    readonly entityType: string;
    /**
     * Identifier of the association.
     */
    readonly id: string;
    readonly serviceCatalogAssociationId: string;
    /**
     * Identifier of the service catalog.
     */
    readonly serviceCatalogId: string;
    /**
     * Timestamp of when the resource was associated with service catalog.
     */
    readonly timeCreated: string;
}
