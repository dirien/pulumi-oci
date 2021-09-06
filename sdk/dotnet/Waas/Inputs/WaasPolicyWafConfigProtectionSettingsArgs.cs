// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class WaasPolicyWafConfigProtectionSettingsArgs : Pulumi.ResourceArgs
    {
        [Input("allowedHttpMethods")]
        private InputList<string>? _allowedHttpMethods;

        /// <summary>
        /// (Updatable) The list of allowed HTTP methods. If unspecified, default to `[OPTIONS, GET, HEAD, POST]`. This setting only applies if a corresponding protection rule is enabled, such as the "Restrict HTTP Request Methods" rule (key: 911100).
        /// </summary>
        public InputList<string> AllowedHttpMethods
        {
            get => _allowedHttpMethods ?? (_allowedHttpMethods = new InputList<string>());
            set => _allowedHttpMethods = value;
        }

        /// <summary>
        /// (Updatable) If `action` is set to `BLOCK`, this specifies how the traffic is blocked when detected as malicious by a protection rule. If unspecified, defaults to `SET_RESPONSE_CODE`.
        /// </summary>
        [Input("blockAction")]
        public Input<string>? BlockAction { get; set; }

        /// <summary>
        /// (Updatable) The error code to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`.
        /// </summary>
        [Input("blockErrorPageCode")]
        public Input<string>? BlockErrorPageCode { get; set; }

        /// <summary>
        /// (Updatable) The description text to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `Access blocked by website owner. Please contact support.`
        /// </summary>
        [Input("blockErrorPageDescription")]
        public Input<string>? BlockErrorPageDescription { get; set; }

        /// <summary>
        /// (Updatable) The message to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to 'Access to the website is blocked.'
        /// </summary>
        [Input("blockErrorPageMessage")]
        public Input<string>? BlockErrorPageMessage { get; set; }

        /// <summary>
        /// (Updatable) The response code returned when `action` is set to `BLOCK`, `blockAction` is set to `SET_RESPONSE_CODE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`. The list of available response codes: `400`, `401`, `403`, `405`, `409`, `411`, `412`, `413`, `414`, `415`, `416`, `500`, `501`, `502`, `503`, `504`, `507`.
        /// </summary>
        [Input("blockResponseCode")]
        public Input<int>? BlockResponseCode { get; set; }

        /// <summary>
        /// (Updatable) Inspects the response body of origin responses. Can be used to detect leakage of sensitive data. If unspecified, defaults to `false`.
        /// </summary>
        [Input("isResponseInspected")]
        public Input<bool>? IsResponseInspected { get; set; }

        /// <summary>
        /// (Updatable) The maximum number of arguments allowed to be passed to your application before an action is taken. Arguements are query parameters or body parameters in a PUT or POST request. If unspecified, defaults to `255`. This setting only applies if a corresponding protection rule is enabled, such as the "Number of Arguments Limits" rule (key: 960335).  Example: If `maxArgumentCount` to `2` for the Max Number of Arguments protection rule (key: 960335), the following requests would be blocked: `GET /myapp/path?query=one&amp;query=two&amp;query=three` `POST /myapp/path` with Body `{"argument1":"one","argument2":"two","argument3":"three"}`
        /// </summary>
        [Input("maxArgumentCount")]
        public Input<int>? MaxArgumentCount { get; set; }

        /// <summary>
        /// (Updatable) The maximum length allowed for each argument name, in characters. Arguements are query parameters or body parameters in a PUT or POST request. If unspecified, defaults to `400`. This setting only applies if a corresponding protection rule is enabled, such as the "Values Limits" rule (key: 960208).
        /// </summary>
        [Input("maxNameLengthPerArgument")]
        public Input<int>? MaxNameLengthPerArgument { get; set; }

        /// <summary>
        /// (Updatable) The maximum response size to be fully inspected, in binary kilobytes (KiB). Anything over this limit will be partially inspected. If unspecified, defaults to `1024`.
        /// </summary>
        [Input("maxResponseSizeInKiB")]
        public Input<int>? MaxResponseSizeInKiB { get; set; }

        /// <summary>
        /// (Updatable) The maximum length allowed for the sum of the argument name and value, in characters. Arguements are query parameters or body parameters in a PUT or POST request. If unspecified, defaults to `64000`. This setting only applies if a corresponding protection rule is enabled, such as the "Total Arguments Limits" rule (key: 960341).
        /// </summary>
        [Input("maxTotalNameLengthOfArguments")]
        public Input<int>? MaxTotalNameLengthOfArguments { get; set; }

        [Input("mediaTypes")]
        private InputList<string>? _mediaTypes;

        /// <summary>
        /// (Updatable) The list of media types to allow for inspection, if `isResponseInspected` is enabled. Only responses with MIME types in this list will be inspected. If unspecified, defaults to `["text/html", "text/plain", "text/xml"]`.
        /// </summary>
        public InputList<string> MediaTypes
        {
            get => _mediaTypes ?? (_mediaTypes = new InputList<string>());
            set => _mediaTypes = value;
        }

        /// <summary>
        /// (Updatable) The length of time to analyze traffic traffic, in days. After the analysis period, `WafRecommendations` will be populated. If unspecified, defaults to `10`.
        /// </summary>
        [Input("recommendationsPeriodInDays")]
        public Input<int>? RecommendationsPeriodInDays { get; set; }

        public WaasPolicyWafConfigProtectionSettingsArgs()
        {
        }
    }
}
