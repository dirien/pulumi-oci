// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Unified Agent Configuration resource in Oracle Cloud Infrastructure Logging service.
 *
 * Create unified agent configuration registration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUnifiedAgentConfiguration = new oci.logging.UnifiedAgentConfiguration("testUnifiedAgentConfiguration", {
 *     compartmentId: _var.compartment_id,
 *     isEnabled: _var.unified_agent_configuration_is_enabled,
 *     description: _var.unified_agent_configuration_description,
 *     displayName: _var.unified_agent_configuration_display_name,
 *     serviceConfiguration: {
 *         configurationType: _var.unified_agent_configuration_service_configuration_configuration_type,
 *         destination: {
 *             logObjectId: oci_objectstorage_object.test_object.id,
 *         },
 *         sources: [{
 *             sourceType: _var.unified_agent_configuration_service_configuration_sources_source_type,
 *             channels: _var.unified_agent_configuration_service_configuration_sources_channels,
 *             name: _var.unified_agent_configuration_service_configuration_sources_name,
 *             parser: {
 *                 parserType: _var.unified_agent_configuration_service_configuration_sources_parser_parser_type,
 *                 delimiter: _var.unified_agent_configuration_service_configuration_sources_parser_delimiter,
 *                 expression: _var.unified_agent_configuration_service_configuration_sources_parser_expression,
 *                 fieldTimeKey: _var.unified_agent_configuration_service_configuration_sources_parser_field_time_key,
 *                 formats: _var.unified_agent_configuration_service_configuration_sources_parser_format,
 *                 formatFirstline: _var.unified_agent_configuration_service_configuration_sources_parser_format_firstline,
 *                 grokFailureKey: _var.unified_agent_configuration_service_configuration_sources_parser_grok_failure_key,
 *                 grokNameKey: _var.unified_agent_configuration_service_configuration_sources_parser_grok_name_key,
 *                 isEstimateCurrentEvent: _var.unified_agent_configuration_service_configuration_sources_parser_is_estimate_current_event,
 *                 isKeepTimeKey: _var.unified_agent_configuration_service_configuration_sources_parser_is_keep_time_key,
 *                 isNullEmptyString: _var.unified_agent_configuration_service_configuration_sources_parser_is_null_empty_string,
 *                 isSupportColonlessIdent: _var.unified_agent_configuration_service_configuration_sources_parser_is_support_colonless_ident,
 *                 isWithPriority: _var.unified_agent_configuration_service_configuration_sources_parser_is_with_priority,
 *                 keys: _var.unified_agent_configuration_service_configuration_sources_parser_keys,
 *                 messageFormat: _var.unified_agent_configuration_service_configuration_sources_parser_message_format,
 *                 messageKey: _var.unified_agent_configuration_service_configuration_sources_parser_message_key,
 *                 multiLineStartRegexp: _var.unified_agent_configuration_service_configuration_sources_parser_multi_line_start_regexp,
 *                 nullValuePattern: _var.unified_agent_configuration_service_configuration_sources_parser_null_value_pattern,
 *                 patterns: [{
 *                     fieldTimeFormat: _var.unified_agent_configuration_service_configuration_sources_parser_patterns_field_time_format,
 *                     fieldTimeKey: _var.unified_agent_configuration_service_configuration_sources_parser_patterns_field_time_key,
 *                     fieldTimeZone: _var.unified_agent_configuration_service_configuration_sources_parser_patterns_field_time_zone,
 *                     name: _var.unified_agent_configuration_service_configuration_sources_parser_patterns_name,
 *                     pattern: _var.unified_agent_configuration_service_configuration_sources_parser_patterns_pattern,
 *                 }],
 *                 rfc5424timeFormat: _var.unified_agent_configuration_service_configuration_sources_parser_rfc5424time_format,
 *                 syslogParserType: _var.unified_agent_configuration_service_configuration_sources_parser_syslog_parser_type,
 *                 timeFormat: _var.unified_agent_configuration_service_configuration_sources_parser_time_format,
 *                 timeType: _var.unified_agent_configuration_service_configuration_sources_parser_time_type,
 *                 timeoutInMilliseconds: _var.unified_agent_configuration_service_configuration_sources_parser_timeout_in_milliseconds,
 *                 types: _var.unified_agent_configuration_service_configuration_sources_parser_types,
 *             },
 *             paths: _var.unified_agent_configuration_service_configuration_sources_paths,
 *         }],
 *     },
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     groupAssociation: {
 *         groupLists: _var.unified_agent_configuration_group_association_group_list,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * UnifiedAgentConfigurations can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:logging/unifiedAgentConfiguration:UnifiedAgentConfiguration test_unified_agent_configuration "id"
 * ```
 */
export class UnifiedAgentConfiguration extends pulumi.CustomResource {
    /**
     * Get an existing UnifiedAgentConfiguration resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: UnifiedAgentConfigurationState, opts?: pulumi.CustomResourceOptions): UnifiedAgentConfiguration {
        return new UnifiedAgentConfiguration(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:logging/unifiedAgentConfiguration:UnifiedAgentConfiguration';

    /**
     * Returns true if the given object is an instance of UnifiedAgentConfiguration.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is UnifiedAgentConfiguration {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === UnifiedAgentConfiguration.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the compartment that the resource belongs to.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * State of unified agent service configuration.
     */
    public /*out*/ readonly configurationState!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Description for this resource.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Groups using the configuration.
     */
    public readonly groupAssociation!: pulumi.Output<outputs.logging.UnifiedAgentConfigurationGroupAssociation>;
    /**
     * (Updatable) Whether or not this resource is currently enabled.
     */
    public readonly isEnabled!: pulumi.Output<boolean>;
    /**
     * (Updatable) Top level Unified Agent service configuration object.
     */
    public readonly serviceConfiguration!: pulumi.Output<outputs.logging.UnifiedAgentConfigurationServiceConfiguration>;
    /**
     * The pipeline state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Time the resource was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Time the resource was last modified.
     */
    public /*out*/ readonly timeLastModified!: pulumi.Output<string>;

    /**
     * Create a UnifiedAgentConfiguration resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: UnifiedAgentConfigurationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: UnifiedAgentConfigurationArgs | UnifiedAgentConfigurationState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as UnifiedAgentConfigurationState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["configurationState"] = state ? state.configurationState : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["groupAssociation"] = state ? state.groupAssociation : undefined;
            inputs["isEnabled"] = state ? state.isEnabled : undefined;
            inputs["serviceConfiguration"] = state ? state.serviceConfiguration : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeLastModified"] = state ? state.timeLastModified : undefined;
        } else {
            const args = argsOrState as UnifiedAgentConfigurationArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.isEnabled === undefined) && !opts.urn) {
                throw new Error("Missing required property 'isEnabled'");
            }
            if ((!args || args.serviceConfiguration === undefined) && !opts.urn) {
                throw new Error("Missing required property 'serviceConfiguration'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["groupAssociation"] = args ? args.groupAssociation : undefined;
            inputs["isEnabled"] = args ? args.isEnabled : undefined;
            inputs["serviceConfiguration"] = args ? args.serviceConfiguration : undefined;
            inputs["configurationState"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeLastModified"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(UnifiedAgentConfiguration.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering UnifiedAgentConfiguration resources.
 */
export interface UnifiedAgentConfigurationState {
    /**
     * (Updatable) The OCID of the compartment that the resource belongs to.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * State of unified agent service configuration.
     */
    configurationState?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Description for this resource.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Groups using the configuration.
     */
    groupAssociation?: pulumi.Input<inputs.logging.UnifiedAgentConfigurationGroupAssociation>;
    /**
     * (Updatable) Whether or not this resource is currently enabled.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) Top level Unified Agent service configuration object.
     */
    serviceConfiguration?: pulumi.Input<inputs.logging.UnifiedAgentConfigurationServiceConfiguration>;
    /**
     * The pipeline state.
     */
    state?: pulumi.Input<string>;
    /**
     * Time the resource was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * Time the resource was last modified.
     */
    timeLastModified?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a UnifiedAgentConfiguration resource.
 */
export interface UnifiedAgentConfigurationArgs {
    /**
     * (Updatable) The OCID of the compartment that the resource belongs to.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Description for this resource.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Groups using the configuration.
     */
    groupAssociation?: pulumi.Input<inputs.logging.UnifiedAgentConfigurationGroupAssociation>;
    /**
     * (Updatable) Whether or not this resource is currently enabled.
     */
    isEnabled: pulumi.Input<boolean>;
    /**
     * (Updatable) Top level Unified Agent service configuration object.
     */
    serviceConfiguration: pulumi.Input<inputs.logging.UnifiedAgentConfigurationServiceConfiguration>;
}
