// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Publication resource in Oracle Cloud Infrastructure Marketplace service.
 *
 * Creates a publication of the given type with an optional default package
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPublication = new oci.marketplace.Publication("testPublication", {
 *     compartmentId: _var.compartment_id,
 *     isAgreementAcknowledged: _var.publication_is_agreement_acknowledged,
 *     listingType: _var.publication_listing_type,
 *     packageDetails: {
 *         eulas: [{
 *             eulaType: _var.publication_package_details_eula_eula_type,
 *             licenseText: _var.publication_package_details_eula_license_text,
 *         }],
 *         operatingSystem: {
 *             name: _var.publication_package_details_operating_system_name,
 *         },
 *         packageType: _var.publication_package_details_package_type,
 *         packageVersion: _var.publication_package_details_package_version,
 *         imageId: oci_core_image.test_image.id,
 *     },
 *     shortDescription: _var.publication_short_description,
 *     supportContacts: [{
 *         email: _var.publication_support_contacts_email,
 *         name: _var.publication_support_contacts_name,
 *         phone: _var.publication_support_contacts_phone,
 *         subject: _var.publication_support_contacts_subject,
 *     }],
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     longDescription: _var.publication_long_description,
 * });
 * ```
 *
 * ## Import
 *
 * Publications can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:marketplace/publication:Publication test_publication "id"
 * ```
 */
export class Publication extends pulumi.CustomResource {
    /**
     * Get an existing Publication resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PublicationState, opts?: pulumi.CustomResourceOptions): Publication {
        return new Publication(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:marketplace/publication:Publication';

    /**
     * Returns true if the given object is an instance of Publication.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Publication {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Publication.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the compartment to create the resource within.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The model for upload data for images and icons.
     */
    public /*out*/ readonly icon!: pulumi.Output<outputs.marketplace.PublicationIcon>;
    /**
     * Acknowledgement that invoker has the right and authority to share this Community Image in accordance with their agreement with Oracle applicable to the Services and the related Service Specifications
     */
    public readonly isAgreementAcknowledged!: pulumi.Output<boolean>;
    /**
     * In which catalog the listing should exist.
     */
    public readonly listingType!: pulumi.Output<string>;
    /**
     * (Updatable) short description of the catalog listing
     */
    public readonly longDescription!: pulumi.Output<string>;
    /**
     * (Updatable) The name of the contact.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * A base object for the properties of the package
     */
    public readonly packageDetails!: pulumi.Output<outputs.marketplace.PublicationPackageDetails>;
    /**
     * Type of the artifact of the listing
     */
    public /*out*/ readonly packageType!: pulumi.Output<string>;
    /**
     * (Updatable) short description of the catalog listing
     */
    public readonly shortDescription!: pulumi.Output<string>;
    /**
     * The state of the listing in its lifecycle
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * (Updatable) Contact information to use to get support from the publisher for the listing.
     */
    public readonly supportContacts!: pulumi.Output<outputs.marketplace.PublicationSupportContact[]>;
    /**
     * List of operating systems supprted.
     */
    public /*out*/ readonly supportedOperatingSystems!: pulumi.Output<outputs.marketplace.PublicationSupportedOperatingSystem[]>;
    /**
     * The date and time this publication was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a Publication resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PublicationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PublicationArgs | PublicationState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as PublicationState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["icon"] = state ? state.icon : undefined;
            inputs["isAgreementAcknowledged"] = state ? state.isAgreementAcknowledged : undefined;
            inputs["listingType"] = state ? state.listingType : undefined;
            inputs["longDescription"] = state ? state.longDescription : undefined;
            inputs["name"] = state ? state.name : undefined;
            inputs["packageDetails"] = state ? state.packageDetails : undefined;
            inputs["packageType"] = state ? state.packageType : undefined;
            inputs["shortDescription"] = state ? state.shortDescription : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["supportContacts"] = state ? state.supportContacts : undefined;
            inputs["supportedOperatingSystems"] = state ? state.supportedOperatingSystems : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as PublicationArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.isAgreementAcknowledged === undefined) && !opts.urn) {
                throw new Error("Missing required property 'isAgreementAcknowledged'");
            }
            if ((!args || args.listingType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'listingType'");
            }
            if ((!args || args.packageDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'packageDetails'");
            }
            if ((!args || args.shortDescription === undefined) && !opts.urn) {
                throw new Error("Missing required property 'shortDescription'");
            }
            if ((!args || args.supportContacts === undefined) && !opts.urn) {
                throw new Error("Missing required property 'supportContacts'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["isAgreementAcknowledged"] = args ? args.isAgreementAcknowledged : undefined;
            inputs["listingType"] = args ? args.listingType : undefined;
            inputs["longDescription"] = args ? args.longDescription : undefined;
            inputs["name"] = args ? args.name : undefined;
            inputs["packageDetails"] = args ? args.packageDetails : undefined;
            inputs["shortDescription"] = args ? args.shortDescription : undefined;
            inputs["supportContacts"] = args ? args.supportContacts : undefined;
            inputs["icon"] = undefined /*out*/;
            inputs["packageType"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["supportedOperatingSystems"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(Publication.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Publication resources.
 */
export interface PublicationState {
    /**
     * (Updatable) The OCID of the compartment to create the resource within.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The model for upload data for images and icons.
     */
    icon?: pulumi.Input<inputs.marketplace.PublicationIcon>;
    /**
     * Acknowledgement that invoker has the right and authority to share this Community Image in accordance with their agreement with Oracle applicable to the Services and the related Service Specifications
     */
    isAgreementAcknowledged?: pulumi.Input<boolean>;
    /**
     * In which catalog the listing should exist.
     */
    listingType?: pulumi.Input<string>;
    /**
     * (Updatable) short description of the catalog listing
     */
    longDescription?: pulumi.Input<string>;
    /**
     * (Updatable) The name of the contact.
     */
    name?: pulumi.Input<string>;
    /**
     * A base object for the properties of the package
     */
    packageDetails?: pulumi.Input<inputs.marketplace.PublicationPackageDetails>;
    /**
     * Type of the artifact of the listing
     */
    packageType?: pulumi.Input<string>;
    /**
     * (Updatable) short description of the catalog listing
     */
    shortDescription?: pulumi.Input<string>;
    /**
     * The state of the listing in its lifecycle
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) Contact information to use to get support from the publisher for the listing.
     */
    supportContacts?: pulumi.Input<pulumi.Input<inputs.marketplace.PublicationSupportContact>[]>;
    /**
     * List of operating systems supprted.
     */
    supportedOperatingSystems?: pulumi.Input<pulumi.Input<inputs.marketplace.PublicationSupportedOperatingSystem>[]>;
    /**
     * The date and time this publication was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Publication resource.
 */
export interface PublicationArgs {
    /**
     * (Updatable) The OCID of the compartment to create the resource within.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Acknowledgement that invoker has the right and authority to share this Community Image in accordance with their agreement with Oracle applicable to the Services and the related Service Specifications
     */
    isAgreementAcknowledged: pulumi.Input<boolean>;
    /**
     * In which catalog the listing should exist.
     */
    listingType: pulumi.Input<string>;
    /**
     * (Updatable) short description of the catalog listing
     */
    longDescription?: pulumi.Input<string>;
    /**
     * (Updatable) The name of the contact.
     */
    name?: pulumi.Input<string>;
    /**
     * A base object for the properties of the package
     */
    packageDetails: pulumi.Input<inputs.marketplace.PublicationPackageDetails>;
    /**
     * (Updatable) short description of the catalog listing
     */
    shortDescription: pulumi.Input<string>;
    /**
     * (Updatable) Contact information to use to get support from the publisher for the listing.
     */
    supportContacts: pulumi.Input<pulumi.Input<inputs.marketplace.PublicationSupportContact>[]>;
}
