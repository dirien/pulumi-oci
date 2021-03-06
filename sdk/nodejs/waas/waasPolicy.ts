// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Waas Policy resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
 *
 * Creates a new Web Application Acceleration and Security (WAAS) policy in the specified compartment. A WAAS policy must be established before creating Web Application Firewall (WAF) rules. To use WAF rules, your web application's origin servers must defined in the `WaasPolicy` schema.
 *
 * A domain name must be specified when creating a WAAS policy. The domain name should be different from the origins specified in your `WaasPolicy`. Once domain name is entered and stored, it is unchangeable.
 *
 * Use the record data returned in the `cname` field of the `WaasPolicy` object to create a CNAME record in your DNS configuration that will direct your domain's traffic through the WAF.
 *
 * For the purposes of access control, you must provide the OCID of the compartment where you want the service to reside. For information about access control and compartments, see [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
 *
 * You must specify a display name and domain for the WAAS policy. The display name does not have to be unique and can be changed. The domain name should be different from every origin specified in `WaasPolicy`.
 *
 * All Oracle Cloud Infrastructure resources, including WAAS policies, receive a unique, Oracle-assigned ID called an Oracle Cloud Identifier (OCID). When a resource is created, you can find its OCID in the response. You can also retrieve a resource's OCID by using a list API operation for that resource type, or by viewing the resource in the Console. Fore more information, see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * **Note:** After sending the POST request, the new object's state will temporarily be `CREATING`. Ensure that the resource's state has changed to `ACTIVE` before use.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWaasPolicy = new oci.waas.WaasPolicy("testWaasPolicy", {
 *     compartmentId: _var.compartment_id,
 *     domain: _var.waas_policy_domain,
 *     additionalDomains: _var.waas_policy_additional_domains,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: _var.waas_policy_display_name,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     originGroups: [{
 *         origins: _var.waas_policy_origin_groups_origins,
 *     }],
 *     origins: [{
 *         uri: _var.waas_policy_origins_uri,
 *         customHeaders: [{
 *             name: _var.waas_policy_origins_custom_headers_name,
 *             value: _var.waas_policy_origins_custom_headers_value,
 *         }],
 *         httpPort: _var.waas_policy_origins_http_port,
 *         httpsPort: _var.waas_policy_origins_https_port,
 *     }],
 *     policyConfig: {
 *         certificateId: oci_waas_certificate.test_certificate.id,
 *         cipherGroup: _var.waas_policy_policy_config_cipher_group,
 *         clientAddressHeader: _var.waas_policy_policy_config_client_address_header,
 *         healthChecks: {
 *             expectedResponseCodeGroups: _var.waas_policy_policy_config_health_checks_expected_response_code_group,
 *             expectedResponseText: _var.waas_policy_policy_config_health_checks_expected_response_text,
 *             headers: _var.waas_policy_policy_config_health_checks_headers,
 *             healthyThreshold: _var.waas_policy_policy_config_health_checks_healthy_threshold,
 *             intervalInSeconds: _var.waas_policy_policy_config_health_checks_interval_in_seconds,
 *             isEnabled: _var.waas_policy_policy_config_health_checks_is_enabled,
 *             isResponseTextCheckEnabled: _var.waas_policy_policy_config_health_checks_is_response_text_check_enabled,
 *             method: _var.waas_policy_policy_config_health_checks_method,
 *             path: _var.waas_policy_policy_config_health_checks_path,
 *             timeoutInSeconds: _var.waas_policy_policy_config_health_checks_timeout_in_seconds,
 *             unhealthyThreshold: _var.waas_policy_policy_config_health_checks_unhealthy_threshold,
 *         },
 *         isBehindCdn: _var.waas_policy_policy_config_is_behind_cdn,
 *         isCacheControlRespected: _var.waas_policy_policy_config_is_cache_control_respected,
 *         isHttpsEnabled: _var.waas_policy_policy_config_is_https_enabled,
 *         isHttpsForced: _var.waas_policy_policy_config_is_https_forced,
 *         isOriginCompressionEnabled: _var.waas_policy_policy_config_is_origin_compression_enabled,
 *         isResponseBufferingEnabled: _var.waas_policy_policy_config_is_response_buffering_enabled,
 *         isSniEnabled: _var.waas_policy_policy_config_is_sni_enabled,
 *         loadBalancingMethod: {
 *             method: _var.waas_policy_policy_config_load_balancing_method_method,
 *             domain: _var.waas_policy_policy_config_load_balancing_method_domain,
 *             expirationTimeInSeconds: _var.waas_policy_policy_config_load_balancing_method_expiration_time_in_seconds,
 *             name: _var.waas_policy_policy_config_load_balancing_method_name,
 *         },
 *         tlsProtocols: _var.waas_policy_policy_config_tls_protocols,
 *         websocketPathPrefixes: _var.waas_policy_policy_config_websocket_path_prefixes,
 *     },
 *     wafConfig: {
 *         accessRules: [{
 *             action: _var.waas_policy_waf_config_access_rules_action,
 *             criterias: [{
 *                 condition: _var.waas_policy_waf_config_access_rules_criteria_condition,
 *                 value: _var.waas_policy_waf_config_access_rules_criteria_value,
 *                 isCaseSensitive: _var.waas_policy_waf_config_access_rules_criteria_is_case_sensitive,
 *             }],
 *             name: _var.waas_policy_waf_config_access_rules_name,
 *             blockAction: _var.waas_policy_waf_config_access_rules_block_action,
 *             blockErrorPageCode: _var.waas_policy_waf_config_access_rules_block_error_page_code,
 *             blockErrorPageDescription: _var.waas_policy_waf_config_access_rules_block_error_page_description,
 *             blockErrorPageMessage: _var.waas_policy_waf_config_access_rules_block_error_page_message,
 *             blockResponseCode: _var.waas_policy_waf_config_access_rules_block_response_code,
 *             bypassChallenges: _var.waas_policy_waf_config_access_rules_bypass_challenges,
 *             captchaFooter: _var.waas_policy_waf_config_access_rules_captcha_footer,
 *             captchaHeader: _var.waas_policy_waf_config_access_rules_captcha_header,
 *             captchaSubmitLabel: _var.waas_policy_waf_config_access_rules_captcha_submit_label,
 *             captchaTitle: _var.waas_policy_waf_config_access_rules_captcha_title,
 *             redirectResponseCode: _var.waas_policy_waf_config_access_rules_redirect_response_code,
 *             redirectUrl: _var.waas_policy_waf_config_access_rules_redirect_url,
 *             responseHeaderManipulations: [{
 *                 action: _var.waas_policy_waf_config_access_rules_response_header_manipulation_action,
 *                 header: _var.waas_policy_waf_config_access_rules_response_header_manipulation_header,
 *                 value: _var.waas_policy_waf_config_access_rules_response_header_manipulation_value,
 *             }],
 *         }],
 *         addressRateLimiting: {
 *             isEnabled: _var.waas_policy_waf_config_address_rate_limiting_is_enabled,
 *             allowedRatePerAddress: _var.waas_policy_waf_config_address_rate_limiting_allowed_rate_per_address,
 *             blockResponseCode: _var.waas_policy_waf_config_address_rate_limiting_block_response_code,
 *             maxDelayedCountPerAddress: _var.waas_policy_waf_config_address_rate_limiting_max_delayed_count_per_address,
 *         },
 *         cachingRules: [{
 *             action: _var.waas_policy_waf_config_caching_rules_action,
 *             criterias: [{
 *                 condition: _var.waas_policy_waf_config_caching_rules_criteria_condition,
 *                 value: _var.waas_policy_waf_config_caching_rules_criteria_value,
 *             }],
 *             name: _var.waas_policy_waf_config_caching_rules_name,
 *             cachingDuration: _var.waas_policy_waf_config_caching_rules_caching_duration,
 *             clientCachingDuration: _var.waas_policy_waf_config_caching_rules_client_caching_duration,
 *             isClientCachingEnabled: _var.waas_policy_waf_config_caching_rules_is_client_caching_enabled,
 *             key: _var.waas_policy_waf_config_caching_rules_key,
 *         }],
 *         captchas: [{
 *             failureMessage: _var.waas_policy_waf_config_captchas_failure_message,
 *             sessionExpirationInSeconds: _var.waas_policy_waf_config_captchas_session_expiration_in_seconds,
 *             submitLabel: _var.waas_policy_waf_config_captchas_submit_label,
 *             title: _var.waas_policy_waf_config_captchas_title,
 *             url: _var.waas_policy_waf_config_captchas_url,
 *             footerText: _var.waas_policy_waf_config_captchas_footer_text,
 *             headerText: _var.waas_policy_waf_config_captchas_header_text,
 *         }],
 *         customProtectionRules: [{
 *             action: _var.waas_policy_waf_config_custom_protection_rules_action,
 *             exclusions: [{
 *                 exclusions: _var.waas_policy_waf_config_custom_protection_rules_exclusions_exclusions,
 *                 target: _var.waas_policy_waf_config_custom_protection_rules_exclusions_target,
 *             }],
 *             id: _var.waas_policy_waf_config_custom_protection_rules_id,
 *         }],
 *         deviceFingerprintChallenge: {
 *             isEnabled: _var.waas_policy_waf_config_device_fingerprint_challenge_is_enabled,
 *             action: _var.waas_policy_waf_config_device_fingerprint_challenge_action,
 *             actionExpirationInSeconds: _var.waas_policy_waf_config_device_fingerprint_challenge_action_expiration_in_seconds,
 *             challengeSettings: {
 *                 blockAction: _var.waas_policy_waf_config_device_fingerprint_challenge_challenge_settings_block_action,
 *                 blockErrorPageCode: _var.waas_policy_waf_config_device_fingerprint_challenge_challenge_settings_block_error_page_code,
 *                 blockErrorPageDescription: _var.waas_policy_waf_config_device_fingerprint_challenge_challenge_settings_block_error_page_description,
 *                 blockErrorPageMessage: _var.waas_policy_waf_config_device_fingerprint_challenge_challenge_settings_block_error_page_message,
 *                 blockResponseCode: _var.waas_policy_waf_config_device_fingerprint_challenge_challenge_settings_block_response_code,
 *                 captchaFooter: _var.waas_policy_waf_config_device_fingerprint_challenge_challenge_settings_captcha_footer,
 *                 captchaHeader: _var.waas_policy_waf_config_device_fingerprint_challenge_challenge_settings_captcha_header,
 *                 captchaSubmitLabel: _var.waas_policy_waf_config_device_fingerprint_challenge_challenge_settings_captcha_submit_label,
 *                 captchaTitle: _var.waas_policy_waf_config_device_fingerprint_challenge_challenge_settings_captcha_title,
 *             },
 *             failureThreshold: _var.waas_policy_waf_config_device_fingerprint_challenge_failure_threshold,
 *             failureThresholdExpirationInSeconds: _var.waas_policy_waf_config_device_fingerprint_challenge_failure_threshold_expiration_in_seconds,
 *             maxAddressCount: _var.waas_policy_waf_config_device_fingerprint_challenge_max_address_count,
 *             maxAddressCountExpirationInSeconds: _var.waas_policy_waf_config_device_fingerprint_challenge_max_address_count_expiration_in_seconds,
 *         },
 *         humanInteractionChallenge: {
 *             isEnabled: _var.waas_policy_waf_config_human_interaction_challenge_is_enabled,
 *             action: _var.waas_policy_waf_config_human_interaction_challenge_action,
 *             actionExpirationInSeconds: _var.waas_policy_waf_config_human_interaction_challenge_action_expiration_in_seconds,
 *             challengeSettings: {
 *                 blockAction: _var.waas_policy_waf_config_human_interaction_challenge_challenge_settings_block_action,
 *                 blockErrorPageCode: _var.waas_policy_waf_config_human_interaction_challenge_challenge_settings_block_error_page_code,
 *                 blockErrorPageDescription: _var.waas_policy_waf_config_human_interaction_challenge_challenge_settings_block_error_page_description,
 *                 blockErrorPageMessage: _var.waas_policy_waf_config_human_interaction_challenge_challenge_settings_block_error_page_message,
 *                 blockResponseCode: _var.waas_policy_waf_config_human_interaction_challenge_challenge_settings_block_response_code,
 *                 captchaFooter: _var.waas_policy_waf_config_human_interaction_challenge_challenge_settings_captcha_footer,
 *                 captchaHeader: _var.waas_policy_waf_config_human_interaction_challenge_challenge_settings_captcha_header,
 *                 captchaSubmitLabel: _var.waas_policy_waf_config_human_interaction_challenge_challenge_settings_captcha_submit_label,
 *                 captchaTitle: _var.waas_policy_waf_config_human_interaction_challenge_challenge_settings_captcha_title,
 *             },
 *             failureThreshold: _var.waas_policy_waf_config_human_interaction_challenge_failure_threshold,
 *             failureThresholdExpirationInSeconds: _var.waas_policy_waf_config_human_interaction_challenge_failure_threshold_expiration_in_seconds,
 *             interactionThreshold: _var.waas_policy_waf_config_human_interaction_challenge_interaction_threshold,
 *             isNatEnabled: _var.waas_policy_waf_config_human_interaction_challenge_is_nat_enabled,
 *             recordingPeriodInSeconds: _var.waas_policy_waf_config_human_interaction_challenge_recording_period_in_seconds,
 *             setHttpHeader: {
 *                 name: _var.waas_policy_waf_config_human_interaction_challenge_set_http_header_name,
 *                 value: _var.waas_policy_waf_config_human_interaction_challenge_set_http_header_value,
 *             },
 *         },
 *         jsChallenge: {
 *             isEnabled: _var.waas_policy_waf_config_js_challenge_is_enabled,
 *             action: _var.waas_policy_waf_config_js_challenge_action,
 *             actionExpirationInSeconds: _var.waas_policy_waf_config_js_challenge_action_expiration_in_seconds,
 *             areRedirectsChallenged: _var.waas_policy_waf_config_js_challenge_are_redirects_challenged,
 *             challengeSettings: {
 *                 blockAction: _var.waas_policy_waf_config_js_challenge_challenge_settings_block_action,
 *                 blockErrorPageCode: _var.waas_policy_waf_config_js_challenge_challenge_settings_block_error_page_code,
 *                 blockErrorPageDescription: _var.waas_policy_waf_config_js_challenge_challenge_settings_block_error_page_description,
 *                 blockErrorPageMessage: _var.waas_policy_waf_config_js_challenge_challenge_settings_block_error_page_message,
 *                 blockResponseCode: _var.waas_policy_waf_config_js_challenge_challenge_settings_block_response_code,
 *                 captchaFooter: _var.waas_policy_waf_config_js_challenge_challenge_settings_captcha_footer,
 *                 captchaHeader: _var.waas_policy_waf_config_js_challenge_challenge_settings_captcha_header,
 *                 captchaSubmitLabel: _var.waas_policy_waf_config_js_challenge_challenge_settings_captcha_submit_label,
 *                 captchaTitle: _var.waas_policy_waf_config_js_challenge_challenge_settings_captcha_title,
 *             },
 *             criterias: [{
 *                 condition: _var.waas_policy_waf_config_js_challenge_criteria_condition,
 *                 value: _var.waas_policy_waf_config_js_challenge_criteria_value,
 *                 isCaseSensitive: _var.waas_policy_waf_config_js_challenge_criteria_is_case_sensitive,
 *             }],
 *             failureThreshold: _var.waas_policy_waf_config_js_challenge_failure_threshold,
 *             isNatEnabled: _var.waas_policy_waf_config_js_challenge_is_nat_enabled,
 *             setHttpHeader: {
 *                 name: _var.waas_policy_waf_config_js_challenge_set_http_header_name,
 *                 value: _var.waas_policy_waf_config_js_challenge_set_http_header_value,
 *             },
 *         },
 *         origin: _var.waas_policy_waf_config_origin,
 *         originGroups: _var.waas_policy_waf_config_origin_groups,
 *         protectionSettings: {
 *             allowedHttpMethods: _var.waas_policy_waf_config_protection_settings_allowed_http_methods,
 *             blockAction: _var.waas_policy_waf_config_protection_settings_block_action,
 *             blockErrorPageCode: _var.waas_policy_waf_config_protection_settings_block_error_page_code,
 *             blockErrorPageDescription: _var.waas_policy_waf_config_protection_settings_block_error_page_description,
 *             blockErrorPageMessage: _var.waas_policy_waf_config_protection_settings_block_error_page_message,
 *             blockResponseCode: _var.waas_policy_waf_config_protection_settings_block_response_code,
 *             isResponseInspected: _var.waas_policy_waf_config_protection_settings_is_response_inspected,
 *             maxArgumentCount: _var.waas_policy_waf_config_protection_settings_max_argument_count,
 *             maxNameLengthPerArgument: _var.waas_policy_waf_config_protection_settings_max_name_length_per_argument,
 *             maxResponseSizeInKiB: _var.waas_policy_waf_config_protection_settings_max_response_size_in_ki_b,
 *             maxTotalNameLengthOfArguments: _var.waas_policy_waf_config_protection_settings_max_total_name_length_of_arguments,
 *             mediaTypes: _var.waas_policy_waf_config_protection_settings_media_types,
 *             recommendationsPeriodInDays: _var.waas_policy_waf_config_protection_settings_recommendations_period_in_days,
 *         },
 *         whitelists: [{
 *             name: _var.waas_policy_waf_config_whitelists_name,
 *             addressLists: _var.waas_policy_waf_config_whitelists_address_lists,
 *             addresses: _var.waas_policy_waf_config_whitelists_addresses,
 *         }],
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * WaasPolicies can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:waas/waasPolicy:WaasPolicy test_waas_policy "id"
 * ```
 */
export class WaasPolicy extends pulumi.CustomResource {
    /**
     * Get an existing WaasPolicy resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: WaasPolicyState, opts?: pulumi.CustomResourceOptions): WaasPolicy {
        return new WaasPolicy(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:waas/waasPolicy:WaasPolicy';

    /**
     * Returns true if the given object is an instance of WaasPolicy.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is WaasPolicy {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === WaasPolicy.__pulumiType;
    }

    /**
     * (Updatable) An array of additional domains for the specified web application.
     */
    public readonly additionalDomains!: pulumi.Output<string[]>;
    /**
     * The CNAME record to add to your DNS configuration to route traffic for the domain, and all additional domains, through the WAF.
     */
    public /*out*/ readonly cname!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the WAAS policy.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name for the WAAS policy. The name can be changed and does not need to be unique.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) The domain for which the cookie is set, defaults to WAAS policy domain.
     */
    public readonly domain!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
     */
    public readonly originGroups!: pulumi.Output<outputs.waas.WaasPolicyOriginGroup[]>;
    /**
     * (Updatable) A map of host to origin for the web application. The key should be a customer friendly name for the host, ex. primary, secondary, etc.
     */
    public readonly origins!: pulumi.Output<outputs.waas.WaasPolicyOrigin[]>;
    /**
     * (Updatable) The configuration details for the WAAS policy.
     */
    public readonly policyConfig!: pulumi.Output<outputs.waas.WaasPolicyPolicyConfig>;
    /**
     * The current lifecycle state of the WAAS policy.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the policy was created, expressed in RFC 3339 timestamp format.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * (Updatable) The Web Application Firewall configuration for the WAAS policy creation.
     */
    public readonly wafConfig!: pulumi.Output<outputs.waas.WaasPolicyWafConfig>;

    /**
     * Create a WaasPolicy resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: WaasPolicyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: WaasPolicyArgs | WaasPolicyState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as WaasPolicyState | undefined;
            inputs["additionalDomains"] = state ? state.additionalDomains : undefined;
            inputs["cname"] = state ? state.cname : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["domain"] = state ? state.domain : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["originGroups"] = state ? state.originGroups : undefined;
            inputs["origins"] = state ? state.origins : undefined;
            inputs["policyConfig"] = state ? state.policyConfig : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["wafConfig"] = state ? state.wafConfig : undefined;
        } else {
            const args = argsOrState as WaasPolicyArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.domain === undefined) && !opts.urn) {
                throw new Error("Missing required property 'domain'");
            }
            inputs["additionalDomains"] = args ? args.additionalDomains : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["domain"] = args ? args.domain : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["originGroups"] = args ? args.originGroups : undefined;
            inputs["origins"] = args ? args.origins : undefined;
            inputs["policyConfig"] = args ? args.policyConfig : undefined;
            inputs["wafConfig"] = args ? args.wafConfig : undefined;
            inputs["cname"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(WaasPolicy.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering WaasPolicy resources.
 */
export interface WaasPolicyState {
    /**
     * (Updatable) An array of additional domains for the specified web application.
     */
    additionalDomains?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The CNAME record to add to your DNS configuration to route traffic for the domain, and all additional domains, through the WAF.
     */
    cname?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the WAAS policy.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name for the WAAS policy. The name can be changed and does not need to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) The domain for which the cookie is set, defaults to WAAS policy domain.
     */
    domain?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
     */
    originGroups?: pulumi.Input<pulumi.Input<inputs.waas.WaasPolicyOriginGroup>[]>;
    /**
     * (Updatable) A map of host to origin for the web application. The key should be a customer friendly name for the host, ex. primary, secondary, etc.
     */
    origins?: pulumi.Input<pulumi.Input<inputs.waas.WaasPolicyOrigin>[]>;
    /**
     * (Updatable) The configuration details for the WAAS policy.
     */
    policyConfig?: pulumi.Input<inputs.waas.WaasPolicyPolicyConfig>;
    /**
     * The current lifecycle state of the WAAS policy.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the policy was created, expressed in RFC 3339 timestamp format.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * (Updatable) The Web Application Firewall configuration for the WAAS policy creation.
     */
    wafConfig?: pulumi.Input<inputs.waas.WaasPolicyWafConfig>;
}

/**
 * The set of arguments for constructing a WaasPolicy resource.
 */
export interface WaasPolicyArgs {
    /**
     * (Updatable) An array of additional domains for the specified web application.
     */
    additionalDomains?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the WAAS policy.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name for the WAAS policy. The name can be changed and does not need to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) The domain for which the cookie is set, defaults to WAAS policy domain.
     */
    domain: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
     */
    originGroups?: pulumi.Input<pulumi.Input<inputs.waas.WaasPolicyOriginGroup>[]>;
    /**
     * (Updatable) A map of host to origin for the web application. The key should be a customer friendly name for the host, ex. primary, secondary, etc.
     */
    origins?: pulumi.Input<pulumi.Input<inputs.waas.WaasPolicyOrigin>[]>;
    /**
     * (Updatable) The configuration details for the WAAS policy.
     */
    policyConfig?: pulumi.Input<inputs.waas.WaasPolicyPolicyConfig>;
    /**
     * (Updatable) The Web Application Firewall configuration for the WAAS policy creation.
     */
    wafConfig?: pulumi.Input<inputs.waas.WaasPolicyWafConfig>;
}
