// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetVmClusterNetworkDownloadConfigFile
    {
        /// <summary>
        /// This data source provides details about a specific Vm Cluster Network Download Config File resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Downloads the configuration file for the specified VM cluster network. Applies to Exadata Cloud@Customer instances only.
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
        ///         var testVmClusterNetworkDownloadConfigFile = Output.Create(Oci.Database.GetVmClusterNetworkDownloadConfigFile.InvokeAsync(new Oci.Database.GetVmClusterNetworkDownloadConfigFileArgs
        ///         {
        ///             ExadataInfrastructureId = oci_database_exadata_infrastructure.Test_exadata_infrastructure.Id,
        ///             VmClusterNetworkId = oci_database_vm_cluster_network.Test_vm_cluster_network.Id,
        ///             Base64EncodeContent = false,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetVmClusterNetworkDownloadConfigFileResult> InvokeAsync(GetVmClusterNetworkDownloadConfigFileArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVmClusterNetworkDownloadConfigFileResult>("oci:database/getVmClusterNetworkDownloadConfigFile:getVmClusterNetworkDownloadConfigFile", args ?? new GetVmClusterNetworkDownloadConfigFileArgs(), options.WithVersion());
    }


    public sealed class GetVmClusterNetworkDownloadConfigFileArgs : Pulumi.InvokeArgs
    {
        [Input("base64EncodeContent")]
        public bool? Base64EncodeContent { get; set; }

        /// <summary>
        /// The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("exadataInfrastructureId", required: true)]
        public string ExadataInfrastructureId { get; set; } = null!;

        /// <summary>
        /// The VM cluster network [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("vmClusterNetworkId", required: true)]
        public string VmClusterNetworkId { get; set; } = null!;

        public GetVmClusterNetworkDownloadConfigFileArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetVmClusterNetworkDownloadConfigFileResult
    {
        public readonly bool? Base64EncodeContent;
        /// <summary>
        /// content of the downloaded config file for exadata infrastructure. If `base64_encode_content` is set to `true`, then this content will be base64 encoded.
        /// </summary>
        public readonly string Content;
        public readonly string ExadataInfrastructureId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string VmClusterNetworkId;

        [OutputConstructor]
        private GetVmClusterNetworkDownloadConfigFileResult(
            bool? base64EncodeContent,

            string content,

            string exadataInfrastructureId,

            string id,

            string vmClusterNetworkId)
        {
            Base64EncodeContent = base64EncodeContent;
            Content = content;
            ExadataInfrastructureId = exadataInfrastructureId;
            Id = id;
            VmClusterNetworkId = vmClusterNetworkId;
        }
    }
}
