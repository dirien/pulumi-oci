// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Gateway resource in Oracle Cloud Infrastructure API Gateway service.
 *
 * Creates a new gateway.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testGateway = new oci.apigateway.Gateway("testGateway", {
 *     compartmentId: _var.compartment_id,
 *     endpointType: _var.gateway_endpoint_type,
 *     subnetId: oci_core_subnet.test_subnet.id,
 *     certificateId: oci_apigateway_certificate.test_certificate.id,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: _var.gateway_display_name,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     responseCacheDetails: {
 *         type: _var.gateway_response_cache_details_type,
 *         authenticationSecretId: oci_vault_secret.test_secret.id,
 *         authenticationSecretVersionNumber: _var.gateway_response_cache_details_authentication_secret_version_number,
 *         connectTimeoutInMs: _var.gateway_response_cache_details_connect_timeout_in_ms,
 *         isSslEnabled: _var.gateway_response_cache_details_is_ssl_enabled,
 *         isSslVerifyDisabled: _var.gateway_response_cache_details_is_ssl_verify_disabled,
 *         readTimeoutInMs: _var.gateway_response_cache_details_read_timeout_in_ms,
 *         sendTimeoutInMs: _var.gateway_response_cache_details_send_timeout_in_ms,
 *         servers: [{
 *             host: _var.gateway_response_cache_details_servers_host,
 *             port: _var.gateway_response_cache_details_servers_port,
 *         }],
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * Gateways can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:apigateway/gateway:Gateway test_gateway "id"
 * ```
 */
export class Gateway extends pulumi.CustomResource {
    /**
     * Get an existing Gateway resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: GatewayState, opts?: pulumi.CustomResourceOptions): Gateway {
        return new Gateway(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:apigateway/gateway:Gateway';

    /**
     * Returns true if the given object is an instance of Gateway.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Gateway {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Gateway.__pulumiType;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     */
    public readonly certificateId!: pulumi.Output<string>;
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
     * Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
     */
    public readonly endpointType!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The hostname for APIs deployed on the gateway.
     */
    public /*out*/ readonly hostname!: pulumi.Output<string>;
    /**
     * An array of IP addresses associated with the gateway.
     */
    public /*out*/ readonly ipAddresses!: pulumi.Output<outputs.apigateway.GatewayIpAddress[]>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) Base Gateway response cache.
     */
    public readonly responseCacheDetails!: pulumi.Output<outputs.apigateway.GatewayResponseCacheDetails>;
    /**
     * The current state of the gateway.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a Gateway resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: GatewayArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: GatewayArgs | GatewayState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as GatewayState | undefined;
            inputs["certificateId"] = state ? state.certificateId : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["endpointType"] = state ? state.endpointType : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["hostname"] = state ? state.hostname : undefined;
            inputs["ipAddresses"] = state ? state.ipAddresses : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["responseCacheDetails"] = state ? state.responseCacheDetails : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["subnetId"] = state ? state.subnetId : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as GatewayArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.endpointType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'endpointType'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            inputs["certificateId"] = args ? args.certificateId : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["endpointType"] = args ? args.endpointType : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["responseCacheDetails"] = args ? args.responseCacheDetails : undefined;
            inputs["subnetId"] = args ? args.subnetId : undefined;
            inputs["hostname"] = undefined /*out*/;
            inputs["ipAddresses"] = undefined /*out*/;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeUpdated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(Gateway.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Gateway resources.
 */
export interface GatewayState {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     */
    certificateId?: pulumi.Input<string>;
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
     * Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
     */
    endpointType?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The hostname for APIs deployed on the gateway.
     */
    hostname?: pulumi.Input<string>;
    /**
     * An array of IP addresses associated with the gateway.
     */
    ipAddresses?: pulumi.Input<pulumi.Input<inputs.apigateway.GatewayIpAddress>[]>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) Base Gateway response cache.
     */
    responseCacheDetails?: pulumi.Input<inputs.apigateway.GatewayResponseCacheDetails>;
    /**
     * The current state of the gateway.
     */
    state?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
     */
    subnetId?: pulumi.Input<string>;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Gateway resource.
 */
export interface GatewayArgs {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     */
    certificateId?: pulumi.Input<string>;
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
     * Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
     */
    endpointType: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Base Gateway response cache.
     */
    responseCacheDetails?: pulumi.Input<inputs.apigateway.GatewayResponseCacheDetails>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
     */
    subnetId: pulumi.Input<string>;
}
