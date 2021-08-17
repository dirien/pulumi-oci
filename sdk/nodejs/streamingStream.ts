// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

/**
 * This resource provides the Stream resource in Oracle Cloud Infrastructure Streaming service.
 *
 * Starts the provisioning of a new stream.
 * The stream will be created in the given compartment id or stream pool id, depending on which parameter is specified.
 * Compartment id and stream pool id cannot be specified at the same time.
 * To track the progress of the provisioning, you can periodically call [GetStream](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/Stream/GetStream).
 * In the response, the `lifecycleState` parameter of the [Stream](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/Stream/) object tells you its current state.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testStream = new oci.StreamingStream("testStream", {
 *     partitions: _var.stream_partitions,
 *     compartmentId: _var.compartment_id,
 *     definedTags: _var.stream_defined_tags,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     retentionInHours: _var.stream_retention_in_hours,
 *     streamPoolId: oci_streaming_stream_pool.test_stream_pool.id,
 * });
 * ```
 *
 * ## Import
 *
 * Streams can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:index/streamingStream:StreamingStream test_stream "id"
 * ```
 */
export class StreamingStream extends pulumi.CustomResource {
    /**
     * Get an existing StreamingStream resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: StreamingStreamState, opts?: pulumi.CustomResourceOptions): StreamingStream {
        return new StreamingStream(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:index/streamingStream:StreamingStream';

    /**
     * Returns true if the given object is an instance of StreamingStream.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is StreamingStream {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === StreamingStream.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the compartment that contains the stream.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Any additional details about the current state of the stream.
     */
    public /*out*/ readonly lifecycleStateDetails!: pulumi.Output<string>;
    /**
     * The endpoint to use when creating the StreamClient to consume or publish messages in the stream. If the associated stream pool is private, the endpoint is also private and can only be accessed from inside the stream pool's associated subnet.
     */
    public /*out*/ readonly messagesEndpoint!: pulumi.Output<string>;
    /**
     * The name of the stream. Avoid entering confidential information.  Example: `TelemetryEvents`
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * The number of partitions in the stream.
     */
    public readonly partitions!: pulumi.Output<number>;
    /**
     * The retention period of the stream, in hours. Accepted values are between 24 and 168 (7 days). If not specified, the stream will have a retention period of 24 hours.
     */
    public readonly retentionInHours!: pulumi.Output<number>;
    /**
     * The current state of the stream.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the stream pool that contains the stream.
     */
    public readonly streamPoolId!: pulumi.Output<string>;
    /**
     * The date and time the stream was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a StreamingStream resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: StreamingStreamArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: StreamingStreamArgs | StreamingStreamState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as StreamingStreamState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["lifecycleStateDetails"] = state ? state.lifecycleStateDetails : undefined;
            inputs["messagesEndpoint"] = state ? state.messagesEndpoint : undefined;
            inputs["name"] = state ? state.name : undefined;
            inputs["partitions"] = state ? state.partitions : undefined;
            inputs["retentionInHours"] = state ? state.retentionInHours : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["streamPoolId"] = state ? state.streamPoolId : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as StreamingStreamArgs | undefined;
            if ((!args || args.partitions === undefined) && !opts.urn) {
                throw new Error("Missing required property 'partitions'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["name"] = args ? args.name : undefined;
            inputs["partitions"] = args ? args.partitions : undefined;
            inputs["retentionInHours"] = args ? args.retentionInHours : undefined;
            inputs["streamPoolId"] = args ? args.streamPoolId : undefined;
            inputs["lifecycleStateDetails"] = undefined /*out*/;
            inputs["messagesEndpoint"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(StreamingStream.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering StreamingStream resources.
 */
export interface StreamingStreamState {
    /**
     * (Updatable) The OCID of the compartment that contains the stream.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Any additional details about the current state of the stream.
     */
    lifecycleStateDetails?: pulumi.Input<string>;
    /**
     * The endpoint to use when creating the StreamClient to consume or publish messages in the stream. If the associated stream pool is private, the endpoint is also private and can only be accessed from inside the stream pool's associated subnet.
     */
    messagesEndpoint?: pulumi.Input<string>;
    /**
     * The name of the stream. Avoid entering confidential information.  Example: `TelemetryEvents`
     */
    name?: pulumi.Input<string>;
    /**
     * The number of partitions in the stream.
     */
    partitions?: pulumi.Input<number>;
    /**
     * The retention period of the stream, in hours. Accepted values are between 24 and 168 (7 days). If not specified, the stream will have a retention period of 24 hours.
     */
    retentionInHours?: pulumi.Input<number>;
    /**
     * The current state of the stream.
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the stream pool that contains the stream.
     */
    streamPoolId?: pulumi.Input<string>;
    /**
     * The date and time the stream was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a StreamingStream resource.
 */
export interface StreamingStreamArgs {
    /**
     * (Updatable) The OCID of the compartment that contains the stream.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The name of the stream. Avoid entering confidential information.  Example: `TelemetryEvents`
     */
    name?: pulumi.Input<string>;
    /**
     * The number of partitions in the stream.
     */
    partitions: pulumi.Input<number>;
    /**
     * The retention period of the stream, in hours. Accepted values are between 24 and 168 (7 days). If not specified, the stream will have a retention period of 24 hours.
     */
    retentionInHours?: pulumi.Input<number>;
    /**
     * (Updatable) The OCID of the stream pool that contains the stream.
     */
    streamPoolId?: pulumi.Input<string>;
}