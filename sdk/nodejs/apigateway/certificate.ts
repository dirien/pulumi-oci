// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Certificate resource in Oracle Cloud Infrastructure API Gateway service.
 *
 * Creates a new Certificate.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCertificate = new oci.apigateway.Certificate("test_certificate", {
 *     //Required
 *     certificate: var_certificate_certificate,
 *     compartmentId: var_compartment_id,
 *     //Optional
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: var_certificate_display_name,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     intermediateCertificates: var_certificate_intermediate_certificates,
 *     privateKey: var_certificate_private_key,
 * });
 * ```
 *
 * ## Import
 *
 * Certificates can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:apigateway/certificate:Certificate test_certificate "id"
 * ```
 */
export class Certificate extends pulumi.CustomResource {
    /**
     * Get an existing Certificate resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: CertificateState, opts?: pulumi.CustomResourceOptions): Certificate {
        return new Certificate(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:apigateway/certificate:Certificate';

    /**
     * Returns true if the given object is an instance of Certificate.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Certificate {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Certificate.__pulumiType;
    }

    /**
     * The data of the leaf certificate in pem format.
     */
    public readonly certificate!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The intermediate certificate data associated with the certificate in pem format.
     */
    public readonly intermediateCertificates!: pulumi.Output<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The private key associated with the certificate in pem format.
     */
    public readonly privateKey!: pulumi.Output<string>;
    /**
     * The current state of the certificate.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The entity to be secured by the certificate and additional host names.
     */
    public /*out*/ readonly subjectNames!: pulumi.Output<string[]>;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the certificate will expire.
     */
    public /*out*/ readonly timeNotValidAfter!: pulumi.Output<string>;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a Certificate resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: CertificateArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: CertificateArgs | CertificateState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as CertificateState | undefined;
            inputs["certificate"] = state ? state.certificate : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["intermediateCertificates"] = state ? state.intermediateCertificates : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["privateKey"] = state ? state.privateKey : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["subjectNames"] = state ? state.subjectNames : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeNotValidAfter"] = state ? state.timeNotValidAfter : undefined;
            inputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as CertificateArgs | undefined;
            if ((!args || args.certificate === undefined) && !opts.urn) {
                throw new Error("Missing required property 'certificate'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.privateKey === undefined) && !opts.urn) {
                throw new Error("Missing required property 'privateKey'");
            }
            inputs["certificate"] = args ? args.certificate : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["intermediateCertificates"] = args ? args.intermediateCertificates : undefined;
            inputs["privateKey"] = args ? args.privateKey : undefined;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["subjectNames"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeNotValidAfter"] = undefined /*out*/;
            inputs["timeUpdated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(Certificate.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Certificate resources.
 */
export interface CertificateState {
    /**
     * The data of the leaf certificate in pem format.
     */
    certificate?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The intermediate certificate data associated with the certificate in pem format.
     */
    intermediateCertificates?: pulumi.Input<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The private key associated with the certificate in pem format.
     */
    privateKey?: pulumi.Input<string>;
    /**
     * The current state of the certificate.
     */
    state?: pulumi.Input<string>;
    /**
     * The entity to be secured by the certificate and additional host names.
     */
    subjectNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the certificate will expire.
     */
    timeNotValidAfter?: pulumi.Input<string>;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Certificate resource.
 */
export interface CertificateArgs {
    /**
     * The data of the leaf certificate in pem format.
     */
    certificate: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The intermediate certificate data associated with the certificate in pem format.
     */
    intermediateCertificates?: pulumi.Input<string>;
    /**
     * The private key associated with the certificate in pem format.
     */
    privateKey: pulumi.Input<string>;
}
