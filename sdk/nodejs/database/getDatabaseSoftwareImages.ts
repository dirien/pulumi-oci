// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Database Software Images in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the database software images in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDatabaseSoftwareImages = oci.database.getDatabaseSoftwareImages({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.database_software_image_display_name,
 *     imageShapeFamily: _var.database_software_image_image_shape_family,
 *     imageType: _var.database_software_image_image_type,
 *     isUpgradeSupported: _var.database_software_image_is_upgrade_supported,
 *     state: _var.database_software_image_state,
 * });
 * ```
 */
export function getDatabaseSoftwareImages(args: GetDatabaseSoftwareImagesArgs, opts?: pulumi.InvokeOptions): Promise<GetDatabaseSoftwareImagesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:database/getDatabaseSoftwareImages:getDatabaseSoftwareImages", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "imageShapeFamily": args.imageShapeFamily,
        "imageType": args.imageType,
        "isUpgradeSupported": args.isUpgradeSupported,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDatabaseSoftwareImages.
 */
export interface GetDatabaseSoftwareImagesArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    filters?: inputs.database.GetDatabaseSoftwareImagesFilter[];
    /**
     * A filter to return only resources that match the given image shape family exactly.
     */
    imageShapeFamily?: string;
    /**
     * A filter to return only resources that match the given image type exactly.
     */
    imageType?: string;
    /**
     * If provided, filters the results to the set of database versions which are supported for Upgrade.
     */
    isUpgradeSupported?: boolean;
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: string;
}

/**
 * A collection of values returned by getDatabaseSoftwareImages.
 */
export interface GetDatabaseSoftwareImagesResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The list of database_software_images.
     */
    readonly databaseSoftwareImages: outputs.database.GetDatabaseSoftwareImagesDatabaseSoftwareImage[];
    /**
     * The user-friendly name for the database software image. The name does not have to be unique.
     */
    readonly displayName?: string;
    readonly filters?: outputs.database.GetDatabaseSoftwareImagesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * To what shape the image is meant for.
     */
    readonly imageShapeFamily?: string;
    /**
     * The type of software image. Can be grid or database.
     */
    readonly imageType?: string;
    /**
     * True if this Database software image is supported for Upgrade.
     */
    readonly isUpgradeSupported?: boolean;
    /**
     * The current state of the database software image.
     */
    readonly state?: string;
}
