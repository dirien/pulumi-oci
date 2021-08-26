// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Model resource in Oracle Cloud Infrastructure Data Science service.
 *
 * Gets the specified model's information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testModel = oci.datascience.getModel({
 *     modelId: oci_datascience_model.test_model.id,
 * });
 * ```
 */
export function getModel(args: GetModelArgs, opts?: pulumi.InvokeOptions): Promise<GetModelResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:datascience/getModel:getModel", {
        "modelId": args.modelId,
    }, opts);
}

/**
 * A collection of arguments for invoking getModel.
 */
export interface GetModelArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
     */
    modelId: string;
}

/**
 * A collection of values returned by getModel.
 */
export interface GetModelResult {
    readonly artifactContentDisposition: string;
    readonly artifactContentLength: string;
    readonly artifactContentMd5: string;
    readonly artifactLastModified: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model's compartment.
     */
    readonly compartmentId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model.
     */
    readonly createdBy: string;
    /**
     * An array of custom metadata details for the model.
     */
    readonly customMetadataLists: outputs.datascience.GetModelCustomMetadataList[];
    /**
     * An array of defined metadata details for the model.
     */
    readonly definedMetadataLists: outputs.datascience.GetModelDefinedMetadataList[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A short description of the model.
     */
    readonly description: string;
    /**
     * A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
     */
    readonly displayName: string;
    readonly emptyModel: boolean;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
     */
    readonly id: string;
    /**
     * Input schema file content in String format
     */
    readonly inputSchema: string;
    readonly modelArtifact: string;
    readonly modelId: string;
    /**
     * Output schema file content in String format
     */
    readonly outputSchema: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the model.
     */
    readonly projectId: string;
    /**
     * The state of the model.
     */
    readonly state: string;
    /**
     * The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
     */
    readonly timeCreated: string;
}