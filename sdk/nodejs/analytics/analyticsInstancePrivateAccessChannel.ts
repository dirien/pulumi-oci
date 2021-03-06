// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Analytics Instance Private Access Channel resource in Oracle Cloud Infrastructure Analytics service.
 *
 * Create a Private access Channel for the Analytics instance. The operation is long-running
 * and creates a new WorkRequest.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAnalyticsInstancePrivateAccessChannel = new oci.analytics.AnalyticsInstancePrivateAccessChannel("testAnalyticsInstancePrivateAccessChannel", {
 *     analyticsInstanceId: oci_analytics_analytics_instance.test_analytics_instance.id,
 *     displayName: _var.analytics_instance_private_access_channel_display_name,
 *     privateSourceDnsZones: [{
 *         dnsZone: _var.analytics_instance_private_access_channel_private_source_dns_zones_dns_zone,
 *         description: _var.analytics_instance_private_access_channel_private_source_dns_zones_description,
 *     }],
 *     subnetId: oci_core_subnet.test_subnet.id,
 *     vcnId: oci_core_vcn.test_vcn.id,
 * });
 * ```
 *
 * ## Import
 *
 * AnalyticsInstancePrivateAccessChannels can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:analytics/analyticsInstancePrivateAccessChannel:AnalyticsInstancePrivateAccessChannel test_analytics_instance_private_access_channel "analyticsInstances/{analyticsInstanceId}/privateAccessChannels/{privateAccessChannelKey}"
 * ```
 */
export class AnalyticsInstancePrivateAccessChannel extends pulumi.CustomResource {
    /**
     * Get an existing AnalyticsInstancePrivateAccessChannel resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AnalyticsInstancePrivateAccessChannelState, opts?: pulumi.CustomResourceOptions): AnalyticsInstancePrivateAccessChannel {
        return new AnalyticsInstancePrivateAccessChannel(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:analytics/analyticsInstancePrivateAccessChannel:AnalyticsInstancePrivateAccessChannel';

    /**
     * Returns true if the given object is an instance of AnalyticsInstancePrivateAccessChannel.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AnalyticsInstancePrivateAccessChannel {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AnalyticsInstancePrivateAccessChannel.__pulumiType;
    }

    /**
     * The OCID of the AnalyticsInstance.
     */
    public readonly analyticsInstanceId!: pulumi.Output<string>;
    /**
     * (Updatable) Display Name of the Private Access Channel.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The list of IP addresses from the customer subnet connected to private access channel, used as a source Ip by Private Access Channel for network traffic from the AnalyticsInstance to Private Sources.
     */
    public /*out*/ readonly egressSourceIpAddresses!: pulumi.Output<string[]>;
    /**
     * IP Address of the Private Access channel.
     */
    public /*out*/ readonly ipAddress!: pulumi.Output<string>;
    /**
     * Private Access Channel unique identifier key.
     */
    public /*out*/ readonly key!: pulumi.Output<string>;
    /**
     * (Updatable) List of Private Source DNS zones registered with Private Access Channel, where datasource hostnames from these dns zones / domains will be resolved in the peered VCN for access from Analytics Instance. Min of 1 is required and Max of 30 Private Source DNS zones can be registered.
     */
    public readonly privateSourceDnsZones!: pulumi.Output<outputs.analytics.AnalyticsInstancePrivateAccessChannelPrivateSourceDnsZone[]>;
    /**
     * (Updatable) OCID of the customer subnet connected to private access channel.
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * (Updatable) OCID of the customer VCN peered with private access channel.
     */
    public readonly vcnId!: pulumi.Output<string>;

    /**
     * Create a AnalyticsInstancePrivateAccessChannel resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AnalyticsInstancePrivateAccessChannelArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AnalyticsInstancePrivateAccessChannelArgs | AnalyticsInstancePrivateAccessChannelState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AnalyticsInstancePrivateAccessChannelState | undefined;
            inputs["analyticsInstanceId"] = state ? state.analyticsInstanceId : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["egressSourceIpAddresses"] = state ? state.egressSourceIpAddresses : undefined;
            inputs["ipAddress"] = state ? state.ipAddress : undefined;
            inputs["key"] = state ? state.key : undefined;
            inputs["privateSourceDnsZones"] = state ? state.privateSourceDnsZones : undefined;
            inputs["subnetId"] = state ? state.subnetId : undefined;
            inputs["vcnId"] = state ? state.vcnId : undefined;
        } else {
            const args = argsOrState as AnalyticsInstancePrivateAccessChannelArgs | undefined;
            if ((!args || args.analyticsInstanceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'analyticsInstanceId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.privateSourceDnsZones === undefined) && !opts.urn) {
                throw new Error("Missing required property 'privateSourceDnsZones'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            if ((!args || args.vcnId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'vcnId'");
            }
            inputs["analyticsInstanceId"] = args ? args.analyticsInstanceId : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["privateSourceDnsZones"] = args ? args.privateSourceDnsZones : undefined;
            inputs["subnetId"] = args ? args.subnetId : undefined;
            inputs["vcnId"] = args ? args.vcnId : undefined;
            inputs["egressSourceIpAddresses"] = undefined /*out*/;
            inputs["ipAddress"] = undefined /*out*/;
            inputs["key"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(AnalyticsInstancePrivateAccessChannel.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AnalyticsInstancePrivateAccessChannel resources.
 */
export interface AnalyticsInstancePrivateAccessChannelState {
    /**
     * The OCID of the AnalyticsInstance.
     */
    analyticsInstanceId?: pulumi.Input<string>;
    /**
     * (Updatable) Display Name of the Private Access Channel.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The list of IP addresses from the customer subnet connected to private access channel, used as a source Ip by Private Access Channel for network traffic from the AnalyticsInstance to Private Sources.
     */
    egressSourceIpAddresses?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * IP Address of the Private Access channel.
     */
    ipAddress?: pulumi.Input<string>;
    /**
     * Private Access Channel unique identifier key.
     */
    key?: pulumi.Input<string>;
    /**
     * (Updatable) List of Private Source DNS zones registered with Private Access Channel, where datasource hostnames from these dns zones / domains will be resolved in the peered VCN for access from Analytics Instance. Min of 1 is required and Max of 30 Private Source DNS zones can be registered.
     */
    privateSourceDnsZones?: pulumi.Input<pulumi.Input<inputs.analytics.AnalyticsInstancePrivateAccessChannelPrivateSourceDnsZone>[]>;
    /**
     * (Updatable) OCID of the customer subnet connected to private access channel.
     */
    subnetId?: pulumi.Input<string>;
    /**
     * (Updatable) OCID of the customer VCN peered with private access channel.
     */
    vcnId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AnalyticsInstancePrivateAccessChannel resource.
 */
export interface AnalyticsInstancePrivateAccessChannelArgs {
    /**
     * The OCID of the AnalyticsInstance.
     */
    analyticsInstanceId: pulumi.Input<string>;
    /**
     * (Updatable) Display Name of the Private Access Channel.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) List of Private Source DNS zones registered with Private Access Channel, where datasource hostnames from these dns zones / domains will be resolved in the peered VCN for access from Analytics Instance. Min of 1 is required and Max of 30 Private Source DNS zones can be registered.
     */
    privateSourceDnsZones: pulumi.Input<pulumi.Input<inputs.analytics.AnalyticsInstancePrivateAccessChannelPrivateSourceDnsZone>[]>;
    /**
     * (Updatable) OCID of the customer subnet connected to private access channel.
     */
    subnetId: pulumi.Input<string>;
    /**
     * (Updatable) OCID of the customer VCN peered with private access channel.
     */
    vcnId: pulumi.Input<string>;
}
