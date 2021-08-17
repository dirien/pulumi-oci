// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetEmailDkims
    {
        /// <summary>
        /// This data source provides the list of Dkims in Oracle Cloud Infrastructure Email service.
        /// 
        /// Lists DKIMs for a email domain.
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
        ///         var testDkims = Output.Create(Oci.GetEmailDkims.InvokeAsync(new Oci.GetEmailDkimsArgs
        ///         {
        ///             EmailDomainId = oci_email_email_domain.Test_email_domain.Id,
        ///             Id = @var.Dkim_id,
        ///             Name = @var.Dkim_name,
        ///             State = @var.Dkim_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetEmailDkimsResult> InvokeAsync(GetEmailDkimsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetEmailDkimsResult>("oci:index/getEmailDkims:GetEmailDkims", args ?? new GetEmailDkimsArgs(), options.WithVersion());
    }


    public sealed class GetEmailDkimsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain to which this DKIM belongs.
        /// </summary>
        [Input("emailDomainId", required: true)]
        public string EmailDomainId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetEmailDkimsFilterArgs>? _filters;
        public List<Inputs.GetEmailDkimsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetEmailDkimsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the given id exactly.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to only return resources that match the given name exactly.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// Filter returned list by specified lifecycle state. This parameter is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetEmailDkimsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetEmailDkimsResult
    {
        /// <summary>
        /// The list of dkim_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetEmailDkimsDkimCollectionResult> DkimCollections;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain that this DKIM belongs to.
        /// </summary>
        public readonly string EmailDomainId;
        public readonly ImmutableArray<Outputs.GetEmailDkimsFilterResult> Filters;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DKIM.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The DKIM selector. If the same domain is managed in more than one region, each region must use different selectors.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The current state of the DKIM.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetEmailDkimsResult(
            ImmutableArray<Outputs.GetEmailDkimsDkimCollectionResult> dkimCollections,

            string emailDomainId,

            ImmutableArray<Outputs.GetEmailDkimsFilterResult> filters,

            string? id,

            string? name,

            string? state)
        {
            DkimCollections = dkimCollections;
            EmailDomainId = emailDomainId;
            Filters = filters;
            Id = id;
            Name = name;
            State = state;
        }
    }
}