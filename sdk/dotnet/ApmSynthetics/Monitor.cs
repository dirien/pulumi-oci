// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics
{
    /// <summary>
    /// This resource provides the Monitor resource in Oracle Cloud Infrastructure Apm Synthetics service.
    /// 
    /// Creates a new monitor.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testMonitor = new Oci.ApmSynthetics.Monitor("testMonitor", new Oci.ApmSynthetics.MonitorArgs
    ///         {
    ///             ApmDomainId = oci_apm_synthetics_apm_domain.Test_apm_domain.Id,
    ///             DisplayName = @var.Monitor_display_name,
    ///             MonitorType = @var.Monitor_monitor_type,
    ///             RepeatIntervalInSeconds = @var.Monitor_repeat_interval_in_seconds,
    ///             VantagePoints = 
    ///             {
    ///                 ,
    ///             },
    ///             Configuration = new Oci.ApmSynthetics.Inputs.MonitorConfigurationArgs
    ///             {
    ///                 ConfigType = @var.Monitor_configuration_config_type,
    ///                 IsCertificateValidationEnabled = @var.Monitor_configuration_is_certificate_validation_enabled,
    ///                 IsFailureRetried = @var.Monitor_configuration_is_failure_retried,
    ///                 IsRedirectionEnabled = @var.Monitor_configuration_is_redirection_enabled,
    ///                 ReqAuthenticationDetails = new Oci.ApmSynthetics.Inputs.MonitorConfigurationReqAuthenticationDetailsArgs
    ///                 {
    ///                     AuthHeaders = 
    ///                     {
    ///                         new Oci.ApmSynthetics.Inputs.MonitorConfigurationReqAuthenticationDetailsAuthHeaderArgs
    ///                         {
    ///                             HeaderName = @var.Monitor_configuration_req_authentication_details_auth_headers_header_name,
    ///                             HeaderValue = @var.Monitor_configuration_req_authentication_details_auth_headers_header_value,
    ///                         },
    ///                     },
    ///                     AuthRequestMethod = @var.Monitor_configuration_req_authentication_details_auth_request_method,
    ///                     AuthRequestPostBody = @var.Monitor_configuration_req_authentication_details_auth_request_post_body,
    ///                     AuthToken = @var.Monitor_configuration_req_authentication_details_auth_token,
    ///                     AuthUrl = @var.Monitor_configuration_req_authentication_details_auth_url,
    ///                     AuthUserName = oci_identity_user.Test_user.Name,
    ///                     AuthUserPassword = @var.Monitor_configuration_req_authentication_details_auth_user_password,
    ///                     OauthScheme = @var.Monitor_configuration_req_authentication_details_oauth_scheme,
    ///                 },
    ///                 ReqAuthenticationScheme = @var.Monitor_configuration_req_authentication_scheme,
    ///                 RequestHeaders = 
    ///                 {
    ///                     new Oci.ApmSynthetics.Inputs.MonitorConfigurationRequestHeaderArgs
    ///                     {
    ///                         HeaderName = @var.Monitor_configuration_request_headers_header_name,
    ///                         HeaderValue = @var.Monitor_configuration_request_headers_header_value,
    ///                     },
    ///                 },
    ///                 RequestMethod = @var.Monitor_configuration_request_method,
    ///                 RequestPostBody = @var.Monitor_configuration_request_post_body,
    ///                 RequestQueryParams = 
    ///                 {
    ///                     new Oci.ApmSynthetics.Inputs.MonitorConfigurationRequestQueryParamArgs
    ///                     {
    ///                         ParamName = @var.Monitor_configuration_request_query_params_param_name,
    ///                         ParamValue = @var.Monitor_configuration_request_query_params_param_value,
    ///                     },
    ///                 },
    ///                 VerifyResponseCodes = @var.Monitor_configuration_verify_response_codes,
    ///                 VerifyResponseContent = @var.Monitor_configuration_verify_response_content,
    ///                 VerifyTexts = 
    ///                 {
    ///                     new Oci.ApmSynthetics.Inputs.MonitorConfigurationVerifyTextArgs
    ///                     {
    ///                         Text = @var.Monitor_configuration_verify_texts_text,
    ///                     },
    ///                 },
    ///             },
    ///             DefinedTags = 
    ///             {
    ///                 { "foo-namespace.bar-key", "value" },
    ///             },
    ///             FreeformTags = 
    ///             {
    ///                 { "bar-key", "value" },
    ///             },
    ///             ScriptId = oci_apm_synthetics_script.Test_script.Id,
    ///             ScriptParameters = 
    ///             {
    ///                 new Oci.ApmSynthetics.Inputs.MonitorScriptParameterArgs
    ///                 {
    ///                     ParamName = @var.Monitor_script_parameters_param_name,
    ///                     ParamValue = @var.Monitor_script_parameters_param_value,
    ///                 },
    ///             },
    ///             Status = @var.Monitor_status,
    ///             Target = @var.Monitor_target,
    ///             TimeoutInSeconds = @var.Monitor_timeout_in_seconds,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Monitors can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:apmsynthetics/monitor:Monitor test_monitor "monitors/{monitorId}/apmDomainId/{apmDomainId}"
    /// ```
    /// </summary>
    [OciResourceType("oci:apmsynthetics/monitor:Monitor")]
    public partial class Monitor : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The APM domain ID the request is intended for.
        /// </summary>
        [Output("apmDomainId")]
        public Output<string> ApmDomainId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Details of monitor configuration.
        /// </summary>
        [Output("configuration")]
        public Output<Outputs.MonitorConfiguration> Configuration { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Unique name that can be edited. The name should not contain any confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Type of monitor.
        /// </summary>
        [Output("monitorType")]
        public Output<string> MonitorType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Interval in seconds after the start time when the job should be repeated. Minimum repeatIntervalInSeconds should be 300 seconds.
        /// </summary>
        [Output("repeatIntervalInSeconds")]
        public Output<int> RepeatIntervalInSeconds { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the script. scriptId is mandatory for creation of SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null.
        /// </summary>
        [Output("scriptId")]
        public Output<string> ScriptId { get; private set; } = null!;

        /// <summary>
        /// Name of the script.
        /// </summary>
        [Output("scriptName")]
        public Output<string> ScriptName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) List of script parameters in the monitor. This is valid only for SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null. Example: `[{"paramName": "userid", "paramValue":"testuser"}]`
        /// </summary>
        [Output("scriptParameters")]
        public Output<ImmutableArray<Outputs.MonitorScriptParameter>> ScriptParameters { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Enables or disables the monitor.
        /// </summary>
        [Output("status")]
        public Output<string> Status { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Specify the endpoint on which to run the monitor. For BROWSER and REST monitor types, target is mandatory. If target is specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script (specified by scriptId in monitor) against the specified target endpoint. If target is not specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script as it is.
        /// </summary>
        [Output("target")]
        public Output<string> Target { get; private set; } = null!;

        /// <summary>
        /// The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Timeout in seconds. Timeout cannot be more than 30% of repeatIntervalInSeconds time for monitors. Also, timeoutInSeconds should be a multiple of 60. Monitor will be allowed to run only for timeoutInSeconds time. It would be terminated after that.
        /// </summary>
        [Output("timeoutInSeconds")]
        public Output<int> TimeoutInSeconds { get; private set; } = null!;

        /// <summary>
        /// Number of vantage points where monitor is running.
        /// </summary>
        [Output("vantagePointCount")]
        public Output<int> VantagePointCount { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A list of vantage points from which to execute the monitor. Use /publicVantagePoints to fetch public vantage points.
        /// </summary>
        [Output("vantagePoints")]
        public Output<ImmutableArray<string>> VantagePoints { get; private set; } = null!;


        /// <summary>
        /// Create a Monitor resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Monitor(string name, MonitorArgs args, CustomResourceOptions? options = null)
            : base("oci:apmsynthetics/monitor:Monitor", name, args ?? new MonitorArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Monitor(string name, Input<string> id, MonitorState? state = null, CustomResourceOptions? options = null)
            : base("oci:apmsynthetics/monitor:Monitor", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing Monitor resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Monitor Get(string name, Input<string> id, MonitorState? state = null, CustomResourceOptions? options = null)
        {
            return new Monitor(name, id, state, options);
        }
    }

    public sealed class MonitorArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The APM domain ID the request is intended for.
        /// </summary>
        [Input("apmDomainId", required: true)]
        public Input<string> ApmDomainId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Details of monitor configuration.
        /// </summary>
        [Input("configuration")]
        public Input<Inputs.MonitorConfigurationArgs>? Configuration { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Unique name that can be edited. The name should not contain any confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Type of monitor.
        /// </summary>
        [Input("monitorType", required: true)]
        public Input<string> MonitorType { get; set; } = null!;

        /// <summary>
        /// (Updatable) Interval in seconds after the start time when the job should be repeated. Minimum repeatIntervalInSeconds should be 300 seconds.
        /// </summary>
        [Input("repeatIntervalInSeconds", required: true)]
        public Input<int> RepeatIntervalInSeconds { get; set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the script. scriptId is mandatory for creation of SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null.
        /// </summary>
        [Input("scriptId")]
        public Input<string>? ScriptId { get; set; }

        /// <summary>
        /// Name of the script.
        /// </summary>
        [Input("scriptName")]
        public Input<string>? ScriptName { get; set; }

        [Input("scriptParameters")]
        private InputList<Inputs.MonitorScriptParameterArgs>? _scriptParameters;

        /// <summary>
        /// (Updatable) List of script parameters in the monitor. This is valid only for SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null. Example: `[{"paramName": "userid", "paramValue":"testuser"}]`
        /// </summary>
        public InputList<Inputs.MonitorScriptParameterArgs> ScriptParameters
        {
            get => _scriptParameters ?? (_scriptParameters = new InputList<Inputs.MonitorScriptParameterArgs>());
            set => _scriptParameters = value;
        }

        /// <summary>
        /// (Updatable) Enables or disables the monitor.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        /// <summary>
        /// (Updatable) Specify the endpoint on which to run the monitor. For BROWSER and REST monitor types, target is mandatory. If target is specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script (specified by scriptId in monitor) against the specified target endpoint. If target is not specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script as it is.
        /// </summary>
        [Input("target")]
        public Input<string>? Target { get; set; }

        /// <summary>
        /// (Updatable) Timeout in seconds. Timeout cannot be more than 30% of repeatIntervalInSeconds time for monitors. Also, timeoutInSeconds should be a multiple of 60. Monitor will be allowed to run only for timeoutInSeconds time. It would be terminated after that.
        /// </summary>
        [Input("timeoutInSeconds")]
        public Input<int>? TimeoutInSeconds { get; set; }

        [Input("vantagePoints", required: true)]
        private InputList<string>? _vantagePoints;

        /// <summary>
        /// (Updatable) A list of vantage points from which to execute the monitor. Use /publicVantagePoints to fetch public vantage points.
        /// </summary>
        public InputList<string> VantagePoints
        {
            get => _vantagePoints ?? (_vantagePoints = new InputList<string>());
            set => _vantagePoints = value;
        }

        public MonitorArgs()
        {
        }
    }

    public sealed class MonitorState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The APM domain ID the request is intended for.
        /// </summary>
        [Input("apmDomainId")]
        public Input<string>? ApmDomainId { get; set; }

        /// <summary>
        /// (Updatable) Details of monitor configuration.
        /// </summary>
        [Input("configuration")]
        public Input<Inputs.MonitorConfigurationGetArgs>? Configuration { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Unique name that can be edited. The name should not contain any confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Type of monitor.
        /// </summary>
        [Input("monitorType")]
        public Input<string>? MonitorType { get; set; }

        /// <summary>
        /// (Updatable) Interval in seconds after the start time when the job should be repeated. Minimum repeatIntervalInSeconds should be 300 seconds.
        /// </summary>
        [Input("repeatIntervalInSeconds")]
        public Input<int>? RepeatIntervalInSeconds { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the script. scriptId is mandatory for creation of SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null.
        /// </summary>
        [Input("scriptId")]
        public Input<string>? ScriptId { get; set; }

        /// <summary>
        /// Name of the script.
        /// </summary>
        [Input("scriptName")]
        public Input<string>? ScriptName { get; set; }

        [Input("scriptParameters")]
        private InputList<Inputs.MonitorScriptParameterGetArgs>? _scriptParameters;

        /// <summary>
        /// (Updatable) List of script parameters in the monitor. This is valid only for SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null. Example: `[{"paramName": "userid", "paramValue":"testuser"}]`
        /// </summary>
        public InputList<Inputs.MonitorScriptParameterGetArgs> ScriptParameters
        {
            get => _scriptParameters ?? (_scriptParameters = new InputList<Inputs.MonitorScriptParameterGetArgs>());
            set => _scriptParameters = value;
        }

        /// <summary>
        /// (Updatable) Enables or disables the monitor.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        /// <summary>
        /// (Updatable) Specify the endpoint on which to run the monitor. For BROWSER and REST monitor types, target is mandatory. If target is specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script (specified by scriptId in monitor) against the specified target endpoint. If target is not specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script as it is.
        /// </summary>
        [Input("target")]
        public Input<string>? Target { get; set; }

        /// <summary>
        /// The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// (Updatable) Timeout in seconds. Timeout cannot be more than 30% of repeatIntervalInSeconds time for monitors. Also, timeoutInSeconds should be a multiple of 60. Monitor will be allowed to run only for timeoutInSeconds time. It would be terminated after that.
        /// </summary>
        [Input("timeoutInSeconds")]
        public Input<int>? TimeoutInSeconds { get; set; }

        /// <summary>
        /// Number of vantage points where monitor is running.
        /// </summary>
        [Input("vantagePointCount")]
        public Input<int>? VantagePointCount { get; set; }

        [Input("vantagePoints")]
        private InputList<string>? _vantagePoints;

        /// <summary>
        /// (Updatable) A list of vantage points from which to execute the monitor. Use /publicVantagePoints to fetch public vantage points.
        /// </summary>
        public InputList<string> VantagePoints
        {
            get => _vantagePoints ?? (_vantagePoints = new InputList<string>());
            set => _vantagePoints = value;
        }

        public MonitorState()
        {
        }
    }
}
