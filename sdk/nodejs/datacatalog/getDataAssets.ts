// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Data Assets in Oracle Cloud Infrastructure Data Catalog service.
 *
 * Returns a list of data assets within a data catalog.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataAssets = oci.datacatalog.getDataAssets({
 *     catalogId: oci_datacatalog_catalog.test_catalog.id,
 *     createdById: oci_datacatalog_created_by.test_created_by.id,
 *     displayName: _var.data_asset_display_name,
 *     displayNameContains: _var.data_asset_display_name_contains,
 *     externalKey: _var.data_asset_external_key,
 *     fields: _var.data_asset_fields,
 *     state: _var.data_asset_state,
 *     timeCreated: _var.data_asset_time_created,
 *     timeUpdated: _var.data_asset_time_updated,
 *     typeKey: _var.data_asset_type_key,
 *     updatedById: oci_datacatalog_updated_by.test_updated_by.id,
 * });
 * ```
 */
export function getDataAssets(args: GetDataAssetsArgs, opts?: pulumi.InvokeOptions): Promise<GetDataAssetsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:datacatalog/getDataAssets:getDataAssets", {
        "catalogId": args.catalogId,
        "createdById": args.createdById,
        "displayName": args.displayName,
        "displayNameContains": args.displayNameContains,
        "externalKey": args.externalKey,
        "fields": args.fields,
        "filters": args.filters,
        "state": args.state,
        "typeKey": args.typeKey,
    }, opts);
}

/**
 * A collection of arguments for invoking getDataAssets.
 */
export interface GetDataAssetsArgs {
    /**
     * Unique catalog identifier.
     */
    catalogId: string;
    /**
     * OCID of the user who created the resource.
     */
    createdById?: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    /**
     * A filter to return only resources that match display name pattern given. The match is not case sensitive. For Example : /folders?displayNameContains=Cu.* The above would match all folders with display name that starts with "Cu".
     */
    displayNameContains?: string;
    /**
     * Unique external identifier of this resource in the external source system.
     */
    externalKey?: string;
    /**
     * Specifies the fields to return in a data asset summary response.
     */
    fields?: string[];
    filters?: inputs.datacatalog.GetDataAssetsFilter[];
    /**
     * A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
     */
    state?: string;
    /**
     * The key of the object type.
     */
    typeKey?: string;
}

/**
 * A collection of values returned by getDataAssets.
 */
export interface GetDataAssetsResult {
    /**
     * The data catalog's OCID.
     */
    readonly catalogId: string;
    /**
     * OCID of the user who created the data asset.
     */
    readonly createdById?: string;
    /**
     * The list of data_asset_collection.
     */
    readonly dataAssetCollections: outputs.datacatalog.GetDataAssetsDataAssetCollection[];
    /**
     * A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly displayNameContains?: string;
    /**
     * External URI that can be used to reference the object. Format will differ based on the type of object.
     */
    readonly externalKey?: string;
    readonly fields?: string[];
    readonly filters?: outputs.datacatalog.GetDataAssetsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the data asset.
     */
    readonly state?: string;
    /**
     * The key of the object type. Type key's can be found via the '/types' endpoint.
     */
    readonly typeKey?: string;
}
