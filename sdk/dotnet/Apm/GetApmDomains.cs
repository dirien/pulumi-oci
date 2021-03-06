// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Apm
{
    public static class GetApmDomains
    {
        /// <summary>
        /// This data source provides the list of Apm Domains in Oracle Cloud Infrastructure Apm service.
        /// 
        /// Lists all APM Domains for the specified tenant compartment.
        /// 
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
        ///         var testApmDomains = Output.Create(Oci.Apm.GetApmDomains.InvokeAsync(new Oci.Apm.GetApmDomainsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Apm_domain_display_name,
        ///             State = @var.Apm_domain_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetApmDomainsResult> InvokeAsync(GetApmDomainsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetApmDomainsResult>("oci:apm/getApmDomains:getApmDomains", args ?? new GetApmDomainsArgs(), options.WithVersion());
    }


    public sealed class GetApmDomainsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetApmDomainsFilterArgs>? _filters;
        public List<Inputs.GetApmDomainsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetApmDomainsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given life-cycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetApmDomainsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetApmDomainsResult
    {
        /// <summary>
        /// The list of apm_domains.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApmDomainsApmDomainResult> ApmDomains;
        /// <summary>
        /// The OCID of the compartment corresponding to the APM Domain.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// APM Domain display name, can be updated.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetApmDomainsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current lifecycle state of the APM Domain.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetApmDomainsResult(
            ImmutableArray<Outputs.GetApmDomainsApmDomainResult> apmDomains,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetApmDomainsFilterResult> filters,

            string id,

            string? state)
        {
            ApmDomains = apmDomains;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
