// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Stream Pool resource in Oracle Cloud Infrastructure Streaming service.
 *
 * Starts the provisioning of a new stream pool.
 * To track the progress of the provisioning, you can periodically call GetStreamPool.
 * In the response, the `lifecycleState` parameter of the object tells you its current state.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testStreamPool = new oci.streaming.StreamPool("testStreamPool", {
 *     compartmentId: _var.compartment_id,
 *     customEncryptionKey: {
 *         kmsKeyId: oci_kms_key.test_key.id,
 *     },
 *     definedTags: _var.stream_pool_defined_tags,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     kafkaSettings: {
 *         autoCreateTopicsEnable: _var.stream_pool_kafka_settings_auto_create_topics_enable,
 *         bootstrapServers: _var.stream_pool_kafka_settings_bootstrap_servers,
 *         logRetentionHours: _var.stream_pool_kafka_settings_log_retention_hours,
 *         numPartitions: _var.stream_pool_kafka_settings_num_partitions,
 *     },
 *     privateEndpointSettings: {
 *         nsgIds: _var.stream_pool_private_endpoint_settings_nsg_ids,
 *         privateEndpointIp: _var.stream_pool_private_endpoint_settings_private_endpoint_ip,
 *         subnetId: oci_core_subnet.test_subnet.id,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * StreamPools can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:streaming/streamPool:StreamPool test_stream_pool "id"
 * ```
 */
export class StreamPool extends pulumi.CustomResource {
    /**
     * Get an existing StreamPool resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: StreamPoolState, opts?: pulumi.CustomResourceOptions): StreamPool {
        return new StreamPool(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:streaming/streamPool:StreamPool';

    /**
     * Returns true if the given object is an instance of StreamPool.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is StreamPool {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === StreamPool.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the compartment that contains the stream.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the custom encryption key to be used or deleted if currently being used.
     */
    public readonly customEncryptionKey!: pulumi.Output<outputs.streaming.StreamPoolCustomEncryptionKey>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The FQDN used to access the streams inside the stream pool (same FQDN as the messagesEndpoint attribute of a [Stream](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/Stream) object). If the stream pool is private, the FQDN is customized and can only be accessed from inside the associated subnetId, otherwise the FQDN is publicly resolvable. Depending on which protocol you attempt to use, you need to either prepend https or append the Kafka port.
     */
    public /*out*/ readonly endpointFqdn!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * True if the stream pool is private, false otherwise. The associated endpoint and subnetId of a private stream pool can be retrieved through the [GetStreamPool](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/StreamPool/GetStreamPool) API.
     */
    public /*out*/ readonly isPrivate!: pulumi.Output<boolean>;
    /**
     * (Updatable) Settings for the Kafka compatibility layer.
     */
    public readonly kafkaSettings!: pulumi.Output<outputs.streaming.StreamPoolKafkaSettings>;
    /**
     * Any additional details about the current state of the stream.
     */
    public /*out*/ readonly lifecycleStateDetails!: pulumi.Output<string>;
    /**
     * (Updatable) The name of the stream pool. Avoid entering confidential information.  Example: `MyStreamPool`
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * Optional parameters if a private stream pool is requested.
     */
    public readonly privateEndpointSettings!: pulumi.Output<outputs.streaming.StreamPoolPrivateEndpointSettings>;
    /**
     * The current state of the stream pool.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the stream pool was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a StreamPool resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: StreamPoolArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: StreamPoolArgs | StreamPoolState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as StreamPoolState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["customEncryptionKey"] = state ? state.customEncryptionKey : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["endpointFqdn"] = state ? state.endpointFqdn : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["isPrivate"] = state ? state.isPrivate : undefined;
            inputs["kafkaSettings"] = state ? state.kafkaSettings : undefined;
            inputs["lifecycleStateDetails"] = state ? state.lifecycleStateDetails : undefined;
            inputs["name"] = state ? state.name : undefined;
            inputs["privateEndpointSettings"] = state ? state.privateEndpointSettings : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as StreamPoolArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["customEncryptionKey"] = args ? args.customEncryptionKey : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["kafkaSettings"] = args ? args.kafkaSettings : undefined;
            inputs["name"] = args ? args.name : undefined;
            inputs["privateEndpointSettings"] = args ? args.privateEndpointSettings : undefined;
            inputs["endpointFqdn"] = undefined /*out*/;
            inputs["isPrivate"] = undefined /*out*/;
            inputs["lifecycleStateDetails"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(StreamPool.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering StreamPool resources.
 */
export interface StreamPoolState {
    /**
     * (Updatable) The OCID of the compartment that contains the stream.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the custom encryption key to be used or deleted if currently being used.
     */
    customEncryptionKey?: pulumi.Input<inputs.streaming.StreamPoolCustomEncryptionKey>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The FQDN used to access the streams inside the stream pool (same FQDN as the messagesEndpoint attribute of a [Stream](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/Stream) object). If the stream pool is private, the FQDN is customized and can only be accessed from inside the associated subnetId, otherwise the FQDN is publicly resolvable. Depending on which protocol you attempt to use, you need to either prepend https or append the Kafka port.
     */
    endpointFqdn?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * True if the stream pool is private, false otherwise. The associated endpoint and subnetId of a private stream pool can be retrieved through the [GetStreamPool](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/StreamPool/GetStreamPool) API.
     */
    isPrivate?: pulumi.Input<boolean>;
    /**
     * (Updatable) Settings for the Kafka compatibility layer.
     */
    kafkaSettings?: pulumi.Input<inputs.streaming.StreamPoolKafkaSettings>;
    /**
     * Any additional details about the current state of the stream.
     */
    lifecycleStateDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The name of the stream pool. Avoid entering confidential information.  Example: `MyStreamPool`
     */
    name?: pulumi.Input<string>;
    /**
     * Optional parameters if a private stream pool is requested.
     */
    privateEndpointSettings?: pulumi.Input<inputs.streaming.StreamPoolPrivateEndpointSettings>;
    /**
     * The current state of the stream pool.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the stream pool was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a StreamPool resource.
 */
export interface StreamPoolArgs {
    /**
     * (Updatable) The OCID of the compartment that contains the stream.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the custom encryption key to be used or deleted if currently being used.
     */
    customEncryptionKey?: pulumi.Input<inputs.streaming.StreamPoolCustomEncryptionKey>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Settings for the Kafka compatibility layer.
     */
    kafkaSettings?: pulumi.Input<inputs.streaming.StreamPoolKafkaSettings>;
    /**
     * (Updatable) The name of the stream pool. Avoid entering confidential information.  Example: `MyStreamPool`
     */
    name?: pulumi.Input<string>;
    /**
     * Optional parameters if a private stream pool is requested.
     */
    privateEndpointSettings?: pulumi.Input<inputs.streaming.StreamPoolPrivateEndpointSettings>;
}
