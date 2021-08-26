// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetKeyStores
    {
        /// <summary>
        /// This data source provides the list of Key Stores in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of key stores in the specified compartment.
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
        ///         var testKeyStores = Output.Create(Oci.Database.GetKeyStores.InvokeAsync(new Oci.Database.GetKeyStoresArgs
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
        public static Task<GetKeyStoresResult> InvokeAsync(GetKeyStoresArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetKeyStoresResult>("oci:database/getKeyStores:getKeyStores", args ?? new GetKeyStoresArgs(), options.WithVersion());
    }


    public sealed class GetKeyStoresArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetKeyStoresFilterArgs>? _filters;
        public List<Inputs.GetKeyStoresFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetKeyStoresFilterArgs>());
            set => _filters = value;
        }

        public GetKeyStoresArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetKeyStoresResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetKeyStoresFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of key_stores.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetKeyStoresKeyStoreResult> KeyStores;

        [OutputConstructor]
        private GetKeyStoresResult(
            string compartmentId,

            ImmutableArray<Outputs.GetKeyStoresFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetKeyStoresKeyStoreResult> keyStores)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            KeyStores = keyStores;
        }
    }
}
