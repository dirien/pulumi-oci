// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Http Monitor resource in Oracle Cloud Infrastructure Health Checks service.
 *
 * Creates an HTTP monitor. Vantage points will be automatically selected if not specified,
 * and probes will be initiated from each vantage point to each of the targets at the frequency
 * specified by `intervalInSeconds`.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testHttpMonitor = new oci.healthchecks.HttpMonitor("testHttpMonitor", {
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.http_monitor_display_name,
 *     intervalInSeconds: _var.http_monitor_interval_in_seconds,
 *     protocol: _var.http_monitor_protocol,
 *     targets: _var.http_monitor_targets,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     headers: _var.http_monitor_headers,
 *     isEnabled: _var.http_monitor_is_enabled,
 *     method: _var.http_monitor_method,
 *     path: _var.http_monitor_path,
 *     port: _var.http_monitor_port,
 *     timeoutInSeconds: _var.http_monitor_timeout_in_seconds,
 *     vantagePointNames: _var.http_monitor_vantage_point_names,
 * });
 * ```
 *
 * ## Import
 *
 * HttpMonitors can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:healthchecks/httpMonitor:HttpMonitor test_http_monitor "id"
 * ```
 */
export class HttpMonitor extends pulumi.CustomResource {
    /**
     * Get an existing HttpMonitor resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: HttpMonitorState, opts?: pulumi.CustomResourceOptions): HttpMonitor {
        return new HttpMonitor(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:healthchecks/httpMonitor:HttpMonitor';

    /**
     * Returns true if the given object is an instance of HttpMonitor.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is HttpMonitor {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === HttpMonitor.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly and mutable name suitable for display in a user interface.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A dictionary of HTTP request headers.
     */
    public readonly headers!: pulumi.Output<{[key: string]: any}>;
    /**
     * The region where updates must be made and where results must be fetched from.
     */
    public /*out*/ readonly homeRegion!: pulumi.Output<string>;
    /**
     * (Updatable) The monitor interval in seconds. Valid values: 10, 30, and 60.
     */
    public readonly intervalInSeconds!: pulumi.Output<number>;
    /**
     * (Updatable) Enables or disables the monitor. Set to 'true' to launch monitoring.
     */
    public readonly isEnabled!: pulumi.Output<boolean>;
    /**
     * (Updatable) The supported HTTP methods available for probes.
     */
    public readonly method!: pulumi.Output<string>;
    /**
     * (Updatable) The optional URL path to probe, including query parameters.
     */
    public readonly path!: pulumi.Output<string>;
    /**
     * (Updatable) The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
     */
    public readonly port!: pulumi.Output<number>;
    /**
     * (Updatable) The supported protocols available for HTTP probes.
     */
    public readonly protocol!: pulumi.Output<string>;
    /**
     * A URL for fetching the probe results.
     */
    public /*out*/ readonly resultsUrl!: pulumi.Output<string>;
    /**
     * (Updatable) A list of targets (hostnames or IP addresses) of the probe.
     */
    public readonly targets!: pulumi.Output<string[]>;
    /**
     * The RFC 3339-formatted creation date and time of the probe.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * (Updatable) The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
     */
    public readonly timeoutInSeconds!: pulumi.Output<number>;
    /**
     * (Updatable) A list of names of vantage points from which to execute the probe.
     */
    public readonly vantagePointNames!: pulumi.Output<string[]>;

    /**
     * Create a HttpMonitor resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: HttpMonitorArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: HttpMonitorArgs | HttpMonitorState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as HttpMonitorState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["headers"] = state ? state.headers : undefined;
            inputs["homeRegion"] = state ? state.homeRegion : undefined;
            inputs["intervalInSeconds"] = state ? state.intervalInSeconds : undefined;
            inputs["isEnabled"] = state ? state.isEnabled : undefined;
            inputs["method"] = state ? state.method : undefined;
            inputs["path"] = state ? state.path : undefined;
            inputs["port"] = state ? state.port : undefined;
            inputs["protocol"] = state ? state.protocol : undefined;
            inputs["resultsUrl"] = state ? state.resultsUrl : undefined;
            inputs["targets"] = state ? state.targets : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeoutInSeconds"] = state ? state.timeoutInSeconds : undefined;
            inputs["vantagePointNames"] = state ? state.vantagePointNames : undefined;
        } else {
            const args = argsOrState as HttpMonitorArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.intervalInSeconds === undefined) && !opts.urn) {
                throw new Error("Missing required property 'intervalInSeconds'");
            }
            if ((!args || args.protocol === undefined) && !opts.urn) {
                throw new Error("Missing required property 'protocol'");
            }
            if ((!args || args.targets === undefined) && !opts.urn) {
                throw new Error("Missing required property 'targets'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["headers"] = args ? args.headers : undefined;
            inputs["intervalInSeconds"] = args ? args.intervalInSeconds : undefined;
            inputs["isEnabled"] = args ? args.isEnabled : undefined;
            inputs["method"] = args ? args.method : undefined;
            inputs["path"] = args ? args.path : undefined;
            inputs["port"] = args ? args.port : undefined;
            inputs["protocol"] = args ? args.protocol : undefined;
            inputs["targets"] = args ? args.targets : undefined;
            inputs["timeoutInSeconds"] = args ? args.timeoutInSeconds : undefined;
            inputs["vantagePointNames"] = args ? args.vantagePointNames : undefined;
            inputs["homeRegion"] = undefined /*out*/;
            inputs["resultsUrl"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(HttpMonitor.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering HttpMonitor resources.
 */
export interface HttpMonitorState {
    /**
     * (Updatable) The OCID of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly and mutable name suitable for display in a user interface.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A dictionary of HTTP request headers.
     */
    headers?: pulumi.Input<{[key: string]: any}>;
    /**
     * The region where updates must be made and where results must be fetched from.
     */
    homeRegion?: pulumi.Input<string>;
    /**
     * (Updatable) The monitor interval in seconds. Valid values: 10, 30, and 60.
     */
    intervalInSeconds?: pulumi.Input<number>;
    /**
     * (Updatable) Enables or disables the monitor. Set to 'true' to launch monitoring.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) The supported HTTP methods available for probes.
     */
    method?: pulumi.Input<string>;
    /**
     * (Updatable) The optional URL path to probe, including query parameters.
     */
    path?: pulumi.Input<string>;
    /**
     * (Updatable) The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
     */
    port?: pulumi.Input<number>;
    /**
     * (Updatable) The supported protocols available for HTTP probes.
     */
    protocol?: pulumi.Input<string>;
    /**
     * A URL for fetching the probe results.
     */
    resultsUrl?: pulumi.Input<string>;
    /**
     * (Updatable) A list of targets (hostnames or IP addresses) of the probe.
     */
    targets?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The RFC 3339-formatted creation date and time of the probe.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * (Updatable) The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
     */
    timeoutInSeconds?: pulumi.Input<number>;
    /**
     * (Updatable) A list of names of vantage points from which to execute the probe.
     */
    vantagePointNames?: pulumi.Input<pulumi.Input<string>[]>;
}

/**
 * The set of arguments for constructing a HttpMonitor resource.
 */
export interface HttpMonitorArgs {
    /**
     * (Updatable) The OCID of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly and mutable name suitable for display in a user interface.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A dictionary of HTTP request headers.
     */
    headers?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The monitor interval in seconds. Valid values: 10, 30, and 60.
     */
    intervalInSeconds: pulumi.Input<number>;
    /**
     * (Updatable) Enables or disables the monitor. Set to 'true' to launch monitoring.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) The supported HTTP methods available for probes.
     */
    method?: pulumi.Input<string>;
    /**
     * (Updatable) The optional URL path to probe, including query parameters.
     */
    path?: pulumi.Input<string>;
    /**
     * (Updatable) The port on which to probe endpoints. If unspecified, probes will use the default port of their protocol.
     */
    port?: pulumi.Input<number>;
    /**
     * (Updatable) The supported protocols available for HTTP probes.
     */
    protocol: pulumi.Input<string>;
    /**
     * (Updatable) A list of targets (hostnames or IP addresses) of the probe.
     */
    targets: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) The probe timeout in seconds. Valid values: 10, 20, 30, and 60. The probe timeout must be less than or equal to `intervalInSeconds` for monitors.
     */
    timeoutInSeconds?: pulumi.Input<number>;
    /**
     * (Updatable) A list of names of vantage points from which to execute the probe.
     */
    vantagePointNames?: pulumi.Input<pulumi.Input<string>[]>;
}
