// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns
{
    public static class GetTsigKeys
    {
        /// <summary>
        /// This data source provides the list of Tsig Keys in Oracle Cloud Infrastructure DNS service.
        /// 
        /// Gets a list of all TSIG keys in the specified compartment.
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
        ///         var testTsigKeys = Output.Create(Oci.Dns.GetTsigKeys.InvokeAsync(new Oci.Dns.GetTsigKeysArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Id = @var.Tsig_key_id,
        ///             Name = @var.Tsig_key_name,
        ///             State = @var.Tsig_key_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetTsigKeysResult> InvokeAsync(GetTsigKeysArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetTsigKeysResult>("oci:dns/getTsigKeys:getTsigKeys", args ?? new GetTsigKeysArgs(), options.WithVersion());
    }


    public sealed class GetTsigKeysArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment the resource belongs to.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetTsigKeysFilterArgs>? _filters;
        public List<Inputs.GetTsigKeysFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetTsigKeysFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of a resource.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// The name of a resource.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// The state of a resource.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetTsigKeysArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetTsigKeysResult
    {
        /// <summary>
        /// The OCID of the compartment containing the TSIG key.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetTsigKeysFilterResult> Filters;
        /// <summary>
        /// The OCID of the resource.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// A globally unique domain name identifying the key for a given pair of hosts.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The current state of the resource.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The list of tsig_keys.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTsigKeysTsigKeyResult> TsigKeys;

        [OutputConstructor]
        private GetTsigKeysResult(
            string compartmentId,

            ImmutableArray<Outputs.GetTsigKeysFilterResult> filters,

            string? id,

            string? name,

            string? state,

            ImmutableArray<Outputs.GetTsigKeysTsigKeyResult> tsigKeys)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            Name = name;
            State = state;
            TsigKeys = tsigKeys;
        }
    }
}
