// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas
{
    public static class GetHttpRedirects
    {
        /// <summary>
        /// This data source provides the list of Http Redirects in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
        /// 
        /// Gets a list of HTTP Redirects.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testHttpRedirects = Output.Create(Oci.Waas.GetHttpRedirects.InvokeAsync(new Oci.Waas.GetHttpRedirectsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayNames = @var.Http_redirect_display_names,
        ///             Ids = @var.Http_redirect_ids,
        ///             States = @var.Http_redirect_states,
        ///             TimeCreatedGreaterThanOrEqualTo = @var.Http_redirect_time_created_greater_than_or_equal_to,
        ///             TimeCreatedLessThan = @var.Http_redirect_time_created_less_than,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetHttpRedirectsResult> InvokeAsync(GetHttpRedirectsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetHttpRedirectsResult>("oci:waas/getHttpRedirects:getHttpRedirects", args ?? new GetHttpRedirectsArgs(), options.WithVersion());
    }


    public sealed class GetHttpRedirectsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("displayNames")]
        private List<string>? _displayNames;

        /// <summary>
        /// Filter redirects using a display name.
        /// </summary>
        public List<string> DisplayNames
        {
            get => _displayNames ?? (_displayNames = new List<string>());
            set => _displayNames = value;
        }

        [Input("filters")]
        private List<Inputs.GetHttpRedirectsFilterArgs>? _filters;
        public List<Inputs.GetHttpRedirectsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetHttpRedirectsFilterArgs>());
            set => _filters = value;
        }

        [Input("ids")]
        private List<string>? _ids;

        /// <summary>
        /// Filter redirects using a list of redirect OCIDs.
        /// </summary>
        public List<string> Ids
        {
            get => _ids ?? (_ids = new List<string>());
            set => _ids = value;
        }

        [Input("states")]
        private List<string>? _states;

        /// <summary>
        /// Filter redirects using a list of lifecycle states.
        /// </summary>
        public List<string> States
        {
            get => _states ?? (_states = new List<string>());
            set => _states = value;
        }

        /// <summary>
        /// A filter that matches redirects created on or after the specified date and time.
        /// </summary>
        [Input("timeCreatedGreaterThanOrEqualTo")]
        public string? TimeCreatedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// A filter that matches redirects created before the specified date-time. Default to 1 day before now.
        /// </summary>
        [Input("timeCreatedLessThan")]
        public string? TimeCreatedLessThan { get; set; }

        public GetHttpRedirectsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetHttpRedirectsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HTTP Redirect's compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<string> DisplayNames;
        public readonly ImmutableArray<Outputs.GetHttpRedirectsFilterResult> Filters;
        /// <summary>
        /// The list of http_redirects.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetHttpRedirectsHttpRedirectResult> HttpRedirects;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly ImmutableArray<string> Ids;
        public readonly ImmutableArray<string> States;
        public readonly string? TimeCreatedGreaterThanOrEqualTo;
        public readonly string? TimeCreatedLessThan;

        [OutputConstructor]
        private GetHttpRedirectsResult(
            string compartmentId,

            ImmutableArray<string> displayNames,

            ImmutableArray<Outputs.GetHttpRedirectsFilterResult> filters,

            ImmutableArray<Outputs.GetHttpRedirectsHttpRedirectResult> httpRedirects,

            string id,

            ImmutableArray<string> ids,

            ImmutableArray<string> states,

            string? timeCreatedGreaterThanOrEqualTo,

            string? timeCreatedLessThan)
        {
            CompartmentId = compartmentId;
            DisplayNames = displayNames;
            Filters = filters;
            HttpRedirects = httpRedirects;
            Id = id;
            Ids = ids;
            States = states;
            TimeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
            TimeCreatedLessThan = timeCreatedLessThan;
        }
    }
}
