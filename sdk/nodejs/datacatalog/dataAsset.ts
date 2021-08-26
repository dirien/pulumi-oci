// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Data Asset resource in Oracle Cloud Infrastructure Data Catalog service.
 *
 * Create a new data asset.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataAsset = new oci.datacatalog.DataAsset("testDataAsset", {
 *     catalogId: oci_datacatalog_catalog.test_catalog.id,
 *     displayName: _var.data_asset_display_name,
 *     typeKey: _var.data_asset_type_key,
 *     description: _var.data_asset_description,
 *     properties: _var.data_asset_properties,
 * });
 * ```
 *
 * ## Import
 *
 * DataAssets can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:datacatalog/dataAsset:DataAsset test_data_asset "catalogs/{catalogId}/dataAssets/{dataAssetKey}"
 * ```
 */
export class DataAsset extends pulumi.CustomResource {
    /**
     * Get an existing DataAsset resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DataAssetState, opts?: pulumi.CustomResourceOptions): DataAsset {
        return new DataAsset(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:datacatalog/dataAsset:DataAsset';

    /**
     * Returns true if the given object is an instance of DataAsset.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DataAsset {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DataAsset.__pulumiType;
    }

    /**
     * Unique catalog identifier.
     */
    public readonly catalogId!: pulumi.Output<string>;
    /**
     * OCID of the user who created the data asset.
     */
    public /*out*/ readonly createdById!: pulumi.Output<string>;
    /**
     * (Updatable) Detailed description of the data asset.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * External URI that can be used to reference the object. Format will differ based on the type of object.
     */
    public /*out*/ readonly externalKey!: pulumi.Output<string>;
    /**
     * Unique data asset key that is immutable.
     */
    public /*out*/ readonly key!: pulumi.Output<string>;
    /**
     * A map of maps that contains the properties which are specific to the asset type. Each data asset type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most data assets have required properties within the "default" category. Example: `{"properties": { "default": { "host": "host1", "port": "1521", "database": "orcl"}}}`
     */
    public readonly properties!: pulumi.Output<{[key: string]: any}>;
    /**
     * The current state of the data asset.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the data asset was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The last time that any change was made to the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * The key of the data asset type. This can be obtained via the '/types' endpoint.
     */
    public readonly typeKey!: pulumi.Output<string>;
    /**
     * OCID of the user who last modified the data asset.
     */
    public /*out*/ readonly updatedById!: pulumi.Output<string>;
    /**
     * URI to the data asset instance in the API.
     */
    public /*out*/ readonly uri!: pulumi.Output<string>;

    /**
     * Create a DataAsset resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DataAssetArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DataAssetArgs | DataAssetState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DataAssetState | undefined;
            inputs["catalogId"] = state ? state.catalogId : undefined;
            inputs["createdById"] = state ? state.createdById : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["externalKey"] = state ? state.externalKey : undefined;
            inputs["key"] = state ? state.key : undefined;
            inputs["properties"] = state ? state.properties : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            inputs["typeKey"] = state ? state.typeKey : undefined;
            inputs["updatedById"] = state ? state.updatedById : undefined;
            inputs["uri"] = state ? state.uri : undefined;
        } else {
            const args = argsOrState as DataAssetArgs | undefined;
            if ((!args || args.catalogId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'catalogId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.typeKey === undefined) && !opts.urn) {
                throw new Error("Missing required property 'typeKey'");
            }
            inputs["catalogId"] = args ? args.catalogId : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["properties"] = args ? args.properties : undefined;
            inputs["typeKey"] = args ? args.typeKey : undefined;
            inputs["createdById"] = undefined /*out*/;
            inputs["externalKey"] = undefined /*out*/;
            inputs["key"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeUpdated"] = undefined /*out*/;
            inputs["updatedById"] = undefined /*out*/;
            inputs["uri"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(DataAsset.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DataAsset resources.
 */
export interface DataAssetState {
    /**
     * Unique catalog identifier.
     */
    catalogId?: pulumi.Input<string>;
    /**
     * OCID of the user who created the data asset.
     */
    createdById?: pulumi.Input<string>;
    /**
     * (Updatable) Detailed description of the data asset.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * External URI that can be used to reference the object. Format will differ based on the type of object.
     */
    externalKey?: pulumi.Input<string>;
    /**
     * Unique data asset key that is immutable.
     */
    key?: pulumi.Input<string>;
    /**
     * A map of maps that contains the properties which are specific to the asset type. Each data asset type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most data assets have required properties within the "default" category. Example: `{"properties": { "default": { "host": "host1", "port": "1521", "database": "orcl"}}}`
     */
    properties?: pulumi.Input<{[key: string]: any}>;
    /**
     * The current state of the data asset.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the data asset was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The last time that any change was made to the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * The key of the data asset type. This can be obtained via the '/types' endpoint.
     */
    typeKey?: pulumi.Input<string>;
    /**
     * OCID of the user who last modified the data asset.
     */
    updatedById?: pulumi.Input<string>;
    /**
     * URI to the data asset instance in the API.
     */
    uri?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DataAsset resource.
 */
export interface DataAssetArgs {
    /**
     * Unique catalog identifier.
     */
    catalogId: pulumi.Input<string>;
    /**
     * (Updatable) Detailed description of the data asset.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName: pulumi.Input<string>;
    /**
     * A map of maps that contains the properties which are specific to the asset type. Each data asset type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most data assets have required properties within the "default" category. Example: `{"properties": { "default": { "host": "host1", "port": "1521", "database": "orcl"}}}`
     */
    properties?: pulumi.Input<{[key: string]: any}>;
    /**
     * The key of the data asset type. This can be obtained via the '/types' endpoint.
     */
    typeKey: pulumi.Input<string>;
}
