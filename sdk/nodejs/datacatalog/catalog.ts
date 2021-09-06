// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Catalog resource in Oracle Cloud Infrastructure Data Catalog service.
 *
 * Creates a new data catalog instance that includes a console and an API URL for managing metadata operations.
 * For more information, please see the documentation.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCatalog = new oci.datacatalog.Catalog("testCatalog", {
 *     compartmentId: _var.compartment_id,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     displayName: _var.catalog_display_name,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * Catalogs can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:datacatalog/catalog:Catalog test_catalog "id"
 * ```
 */
export class Catalog extends pulumi.CustomResource {
    /**
     * Get an existing Catalog resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: CatalogState, opts?: pulumi.CustomResourceOptions): Catalog {
        return new Catalog(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:datacatalog/catalog:Catalog';

    /**
     * Returns true if the given object is an instance of Catalog.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Catalog {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Catalog.__pulumiType;
    }

    /**
     * (Updatable) The list of private reverse connection endpoints attached to the catalog
     */
    public readonly attachedCatalogPrivateEndpoints!: pulumi.Output<string[]>;
    /**
     * (Updatable) Compartment identifier.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Data catalog identifier.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * An message describing the current state in more detail.  For example, it can be used to provide actionable information for a resource in 'Failed' state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The number of data objects added to the data catalog. Please see the data catalog documentation for further information on how this is calculated.
     */
    public /*out*/ readonly numberOfObjects!: pulumi.Output<number>;
    /**
     * The REST front endpoint URL to the data catalog instance.
     */
    public /*out*/ readonly serviceApiUrl!: pulumi.Output<string>;
    /**
     * The console front endpoint URL to the data catalog instance.
     */
    public /*out*/ readonly serviceConsoleUrl!: pulumi.Output<string>;
    /**
     * The current state of the data catalog resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The time the data catalog was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the data catalog was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a Catalog resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: CatalogArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: CatalogArgs | CatalogState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as CatalogState | undefined;
            inputs["attachedCatalogPrivateEndpoints"] = state ? state.attachedCatalogPrivateEndpoints : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["numberOfObjects"] = state ? state.numberOfObjects : undefined;
            inputs["serviceApiUrl"] = state ? state.serviceApiUrl : undefined;
            inputs["serviceConsoleUrl"] = state ? state.serviceConsoleUrl : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as CatalogArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            inputs["attachedCatalogPrivateEndpoints"] = args ? args.attachedCatalogPrivateEndpoints : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["numberOfObjects"] = undefined /*out*/;
            inputs["serviceApiUrl"] = undefined /*out*/;
            inputs["serviceConsoleUrl"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeUpdated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(Catalog.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Catalog resources.
 */
export interface CatalogState {
    /**
     * (Updatable) The list of private reverse connection endpoints attached to the catalog
     */
    attachedCatalogPrivateEndpoints?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) Compartment identifier.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Data catalog identifier.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * An message describing the current state in more detail.  For example, it can be used to provide actionable information for a resource in 'Failed' state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The number of data objects added to the data catalog. Please see the data catalog documentation for further information on how this is calculated.
     */
    numberOfObjects?: pulumi.Input<number>;
    /**
     * The REST front endpoint URL to the data catalog instance.
     */
    serviceApiUrl?: pulumi.Input<string>;
    /**
     * The console front endpoint URL to the data catalog instance.
     */
    serviceConsoleUrl?: pulumi.Input<string>;
    /**
     * The current state of the data catalog resource.
     */
    state?: pulumi.Input<string>;
    /**
     * The time the data catalog was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the data catalog was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Catalog resource.
 */
export interface CatalogArgs {
    /**
     * (Updatable) The list of private reverse connection endpoints attached to the catalog
     */
    attachedCatalogPrivateEndpoints?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) Compartment identifier.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Data catalog identifier.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
}
