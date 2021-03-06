// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the App Catalog Subscription resource in Oracle Cloud Infrastructure Core service.
 *
 * Create a subscription for listing resource version for a compartment. It will take some time to propagate to all regions.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAppCatalogSubscription = new oci.core.AppCatalogSubscription("testAppCatalogSubscription", {
 *     compartmentId: _var.compartment_id,
 *     listingId: data.oci_core_app_catalog_listing.test_listing.id,
 *     listingResourceVersion: _var.app_catalog_subscription_listing_resource_version,
 *     oracleTermsOfUseLink: _var.app_catalog_subscription_oracle_terms_of_use_link,
 *     signature: _var.app_catalog_subscription_signature,
 *     timeRetrieved: _var.app_catalog_subscription_time_retrieved,
 *     eulaLink: _var.app_catalog_subscription_eula_link,
 * });
 * ```
 *
 * ## Import
 *
 * AppCatalogSubscriptions can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:core/appCatalogSubscription:AppCatalogSubscription test_app_catalog_subscription "compartmentId/{compartmentId}/listingId/{listingId}/listingResourceVersion/{listingResourceVersion}"
 * ```
 */
export class AppCatalogSubscription extends pulumi.CustomResource {
    /**
     * Get an existing AppCatalogSubscription resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AppCatalogSubscriptionState, opts?: pulumi.CustomResourceOptions): AppCatalogSubscription {
        return new AppCatalogSubscription(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:core/appCatalogSubscription:AppCatalogSubscription';

    /**
     * Returns true if the given object is an instance of AppCatalogSubscription.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AppCatalogSubscription {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AppCatalogSubscription.__pulumiType;
    }

    /**
     * The compartmentID for the subscription.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The display name of the listing.
     */
    public /*out*/ readonly displayName!: pulumi.Output<string>;
    /**
     * EULA link
     */
    public readonly eulaLink!: pulumi.Output<string | undefined>;
    /**
     * The OCID of the listing.
     */
    public readonly listingId!: pulumi.Output<string>;
    /**
     * Listing resource id.
     */
    public /*out*/ readonly listingResourceId!: pulumi.Output<string>;
    /**
     * Listing resource version.
     */
    public readonly listingResourceVersion!: pulumi.Output<string>;
    /**
     * Oracle TOU link
     */
    public readonly oracleTermsOfUseLink!: pulumi.Output<string>;
    /**
     * Name of the publisher who published this listing.
     */
    public /*out*/ readonly publisherName!: pulumi.Output<string>;
    /**
     * A generated signature for this listing resource version retrieved the agreements API.
     */
    public readonly signature!: pulumi.Output<string>;
    /**
     * The short summary to the listing.
     */
    public /*out*/ readonly summary!: pulumi.Output<string>;
    /**
     * Date and time at which the subscription was created, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Date and time the agreements were retrieved, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
     */
    public readonly timeRetrieved!: pulumi.Output<string>;

    /**
     * Create a AppCatalogSubscription resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AppCatalogSubscriptionArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AppCatalogSubscriptionArgs | AppCatalogSubscriptionState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AppCatalogSubscriptionState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["eulaLink"] = state ? state.eulaLink : undefined;
            inputs["listingId"] = state ? state.listingId : undefined;
            inputs["listingResourceId"] = state ? state.listingResourceId : undefined;
            inputs["listingResourceVersion"] = state ? state.listingResourceVersion : undefined;
            inputs["oracleTermsOfUseLink"] = state ? state.oracleTermsOfUseLink : undefined;
            inputs["publisherName"] = state ? state.publisherName : undefined;
            inputs["signature"] = state ? state.signature : undefined;
            inputs["summary"] = state ? state.summary : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeRetrieved"] = state ? state.timeRetrieved : undefined;
        } else {
            const args = argsOrState as AppCatalogSubscriptionArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.listingId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'listingId'");
            }
            if ((!args || args.listingResourceVersion === undefined) && !opts.urn) {
                throw new Error("Missing required property 'listingResourceVersion'");
            }
            if ((!args || args.oracleTermsOfUseLink === undefined) && !opts.urn) {
                throw new Error("Missing required property 'oracleTermsOfUseLink'");
            }
            if ((!args || args.signature === undefined) && !opts.urn) {
                throw new Error("Missing required property 'signature'");
            }
            if ((!args || args.timeRetrieved === undefined) && !opts.urn) {
                throw new Error("Missing required property 'timeRetrieved'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["eulaLink"] = args ? args.eulaLink : undefined;
            inputs["listingId"] = args ? args.listingId : undefined;
            inputs["listingResourceVersion"] = args ? args.listingResourceVersion : undefined;
            inputs["oracleTermsOfUseLink"] = args ? args.oracleTermsOfUseLink : undefined;
            inputs["signature"] = args ? args.signature : undefined;
            inputs["timeRetrieved"] = args ? args.timeRetrieved : undefined;
            inputs["displayName"] = undefined /*out*/;
            inputs["listingResourceId"] = undefined /*out*/;
            inputs["publisherName"] = undefined /*out*/;
            inputs["summary"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(AppCatalogSubscription.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AppCatalogSubscription resources.
 */
export interface AppCatalogSubscriptionState {
    /**
     * The compartmentID for the subscription.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The display name of the listing.
     */
    displayName?: pulumi.Input<string>;
    /**
     * EULA link
     */
    eulaLink?: pulumi.Input<string>;
    /**
     * The OCID of the listing.
     */
    listingId?: pulumi.Input<string>;
    /**
     * Listing resource id.
     */
    listingResourceId?: pulumi.Input<string>;
    /**
     * Listing resource version.
     */
    listingResourceVersion?: pulumi.Input<string>;
    /**
     * Oracle TOU link
     */
    oracleTermsOfUseLink?: pulumi.Input<string>;
    /**
     * Name of the publisher who published this listing.
     */
    publisherName?: pulumi.Input<string>;
    /**
     * A generated signature for this listing resource version retrieved the agreements API.
     */
    signature?: pulumi.Input<string>;
    /**
     * The short summary to the listing.
     */
    summary?: pulumi.Input<string>;
    /**
     * Date and time at which the subscription was created, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * Date and time the agreements were retrieved, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
     */
    timeRetrieved?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AppCatalogSubscription resource.
 */
export interface AppCatalogSubscriptionArgs {
    /**
     * The compartmentID for the subscription.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * EULA link
     */
    eulaLink?: pulumi.Input<string>;
    /**
     * The OCID of the listing.
     */
    listingId: pulumi.Input<string>;
    /**
     * Listing resource version.
     */
    listingResourceVersion: pulumi.Input<string>;
    /**
     * Oracle TOU link
     */
    oracleTermsOfUseLink: pulumi.Input<string>;
    /**
     * A generated signature for this listing resource version retrieved the agreements API.
     */
    signature: pulumi.Input<string>;
    /**
     * Date and time the agreements were retrieved, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
     */
    timeRetrieved: pulumi.Input<string>;
}
