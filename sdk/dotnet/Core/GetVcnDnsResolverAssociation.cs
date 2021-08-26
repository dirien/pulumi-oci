// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetVcnDnsResolverAssociation
    {
        /// <summary>
        /// This data source provides details about a specific Vcn Dns Resolver Association resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Get the associated DNS resolver information with a vcn
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
        ///         var testVcnDnsResolverAssociation = Output.Create(Oci.Core.GetVcnDnsResolverAssociation.InvokeAsync(new Oci.Core.GetVcnDnsResolverAssociationArgs
        ///         {
        ///             VcnId = oci_core_vcn.Test_vcn.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetVcnDnsResolverAssociationResult> InvokeAsync(GetVcnDnsResolverAssociationArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVcnDnsResolverAssociationResult>("oci:core/getVcnDnsResolverAssociation:getVcnDnsResolverAssociation", args ?? new GetVcnDnsResolverAssociationArgs(), options.WithVersion());
    }


    public sealed class GetVcnDnsResolverAssociationArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        /// </summary>
        [Input("vcnId", required: true)]
        public string VcnId { get; set; } = null!;

        public GetVcnDnsResolverAssociationArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetVcnDnsResolverAssociationResult
    {
        /// <summary>
        /// The OCID of the DNS resolver in the association. We won't have the DNS resolver id as soon as vcn 
        /// is created, we will create it asynchronously. It would be null until it is actually created.
        /// </summary>
        public readonly string DnsResolverId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string State;
        /// <summary>
        /// The OCID of the VCN in the association.
        /// </summary>
        public readonly string VcnId;

        [OutputConstructor]
        private GetVcnDnsResolverAssociationResult(
            string dnsResolverId,

            string id,

            string state,

            string vcnId)
        {
            DnsResolverId = dnsResolverId;
            Id = id;
            State = state;
            VcnId = vcnId;
        }
    }
}
