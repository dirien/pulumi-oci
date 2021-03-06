// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation
{
    public static class GetConfiguration
    {
        /// <summary>
        /// This data source provides details about a specific Configuration resource in Oracle Cloud Infrastructure Metering Computation service.
        /// 
        /// Returns the configurations list for the UI drop-down list.
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
        ///         var testConfiguration = Output.Create(Oci.MeteringComputation.GetConfiguration.InvokeAsync(new Oci.MeteringComputation.GetConfigurationArgs
        ///         {
        ///             TenantId = oci_metering_computation_tenant.Test_tenant.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetConfigurationResult> InvokeAsync(GetConfigurationArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetConfigurationResult>("oci:meteringcomputation/getConfiguration:getConfiguration", args ?? new GetConfigurationArgs(), options.WithVersion());
    }


    public sealed class GetConfigurationArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// tenant id
        /// </summary>
        [Input("tenantId", required: true)]
        public string TenantId { get; set; } = null!;

        public GetConfigurationArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetConfigurationResult
    {
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of available configurations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetConfigurationItemResult> Items;
        public readonly string TenantId;

        [OutputConstructor]
        private GetConfigurationResult(
            string id,

            ImmutableArray<Outputs.GetConfigurationItemResult> items,

            string tenantId)
        {
            Id = id;
            Items = items;
            TenantId = tenantId;
        }
    }
}
