// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway
{
    public static class GetCertificate
    {
        /// <summary>
        /// This data source provides details about a specific Certificate resource in Oracle Cloud Infrastructure API Gateway service.
        /// 
        /// Gets a certificate by identifier.
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
        ///         var testCertificate = Output.Create(Oci.ApiGateway.GetCertificate.InvokeAsync(new Oci.ApiGateway.GetCertificateArgs
        ///         {
        ///             CertificateId = oci_apigateway_certificate.Test_certificate.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetCertificateResult> InvokeAsync(GetCertificateArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetCertificateResult>("oci:apigateway/getCertificate:getCertificate", args ?? new GetCertificateArgs(), options.WithVersion());
    }


    public sealed class GetCertificateArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ocid of the certificate.
        /// </summary>
        [Input("certificateId", required: true)]
        public string CertificateId { get; set; } = null!;

        public GetCertificateArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetCertificateResult
    {
        /// <summary>
        /// The data of the leaf certificate in pem format.
        /// </summary>
        public readonly string Certificate;
        public readonly string CertificateId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The intermediate certificate data associated with the certificate in pem format.
        /// </summary>
        public readonly string IntermediateCertificates;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        public readonly string PrivateKey;
        /// <summary>
        /// The current state of the certificate.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The entity to be secured by the certificate and additional host names.
        /// </summary>
        public readonly ImmutableArray<string> SubjectNames;
        /// <summary>
        /// The time this resource was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the certificate will expire.
        /// </summary>
        public readonly string TimeNotValidAfter;
        /// <summary>
        /// The time this resource was last updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetCertificateResult(
            string certificate,

            string certificateId,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string intermediateCertificates,

            string lifecycleDetails,

            string privateKey,

            string state,

            ImmutableArray<string> subjectNames,

            string timeCreated,

            string timeNotValidAfter,

            string timeUpdated)
        {
            Certificate = certificate;
            CertificateId = certificateId;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IntermediateCertificates = intermediateCertificates;
            LifecycleDetails = lifecycleDetails;
            PrivateKey = privateKey;
            State = state;
            SubjectNames = subjectNames;
            TimeCreated = timeCreated;
            TimeNotValidAfter = timeNotValidAfter;
            TimeUpdated = timeUpdated;
        }
    }
}
