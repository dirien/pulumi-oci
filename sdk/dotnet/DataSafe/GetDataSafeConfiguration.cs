// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetDataSafeConfiguration
    {
        /// <summary>
        /// This data source provides details about a specific Data Safe Configuration resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets the details of the Data Safe configuration.
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
        ///         var testDataSafeConfiguration = Output.Create(Oci.DataSafe.GetDataSafeConfiguration.InvokeAsync(new Oci.DataSafe.GetDataSafeConfigurationArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDataSafeConfigurationResult> InvokeAsync(GetDataSafeConfigurationArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDataSafeConfigurationResult>("oci:datasafe/getDataSafeConfiguration:getDataSafeConfiguration", args ?? new GetDataSafeConfigurationArgs(), options.WithVersion());
    }


    public sealed class GetDataSafeConfigurationArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        public GetDataSafeConfigurationArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDataSafeConfigurationResult
    {
        /// <summary>
        /// The OCID of the tenancy used to enable Data Safe.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string Id;
        /// <summary>
        /// Indicates if Data Safe is enabled.
        /// </summary>
        public readonly bool IsEnabled;
        /// <summary>
        /// The current state of Data Safe.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time Data Safe was enabled, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeEnabled;
        /// <summary>
        /// The URL of the Data Safe service.
        /// </summary>
        public readonly string Url;

        [OutputConstructor]
        private GetDataSafeConfigurationResult(
            string compartmentId,

            string id,

            bool isEnabled,

            string state,

            string timeEnabled,

            string url)
        {
            CompartmentId = compartmentId;
            Id = id;
            IsEnabled = isEnabled;
            State = state;
            TimeEnabled = timeEnabled;
            Url = url;
        }
    }
}
