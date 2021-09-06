// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns
{
    public static class GetResolverEndpoint
    {
        /// <summary>
        /// This data source provides details about a specific Resolver Endpoint resource in Oracle Cloud Infrastructure DNS service.
        /// 
        /// Gets information about a specific resolver endpoint. Note that attempting to get a resolver endpoint
        /// in the DELETED lifecycle state will result in a `404` response to be consistent with other operations of the
        /// API. Requires a `PRIVATE` scope query parameter.
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
        ///         var testResolverEndpoint = Output.Create(Oci.Dns.GetResolverEndpoint.InvokeAsync(new Oci.Dns.GetResolverEndpointArgs
        ///         {
        ///             ResolverEndpointName = oci_dns_resolver_endpoint.Test_resolver_endpoint.Name,
        ///             ResolverId = oci_dns_resolver.Test_resolver.Id,
        ///             Scope = "PRIVATE",
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetResolverEndpointResult> InvokeAsync(GetResolverEndpointArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetResolverEndpointResult>("oci:dns/getResolverEndpoint:getResolverEndpoint", args ?? new GetResolverEndpointArgs(), options.WithVersion());
    }


    public sealed class GetResolverEndpointArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the target resolver endpoint.
        /// </summary>
        [Input("resolverEndpointName", required: true)]
        public string ResolverEndpointName { get; set; } = null!;

        /// <summary>
        /// The OCID of the target resolver.
        /// </summary>
        [Input("resolverId", required: true)]
        public string ResolverId { get; set; } = null!;

        /// <summary>
        /// Value must be `PRIVATE` when listing private name resolver endpoints.
        /// </summary>
        [Input("scope", required: true)]
        public string Scope { get; set; } = null!;

        public GetResolverEndpointArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetResolverEndpointResult
    {
        /// <summary>
        /// The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver's compartment is changed.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The type of resolver endpoint. VNIC is currently the only supported type.
        /// </summary>
        public readonly string EndpointType;
        /// <summary>
        /// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
        /// </summary>
        public readonly string ForwardingAddress;
        public readonly string Id;
        /// <summary>
        /// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
        /// </summary>
        public readonly bool IsForwarding;
        /// <summary>
        /// A Boolean flag indicating whether or not the resolver endpoint is for listening.
        /// </summary>
        public readonly bool IsListening;
        /// <summary>
        /// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
        /// </summary>
        public readonly string ListeningAddress;
        /// <summary>
        /// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        public readonly string ResolverEndpointName;
        public readonly string ResolverId;
        public readonly string Scope;
        /// <summary>
        /// The canonical absolute URL of the resource.
        /// </summary>
        public readonly string Self;
        /// <summary>
        /// The current state of the resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetResolverEndpointResult(
            string compartmentId,

            string endpointType,

            string forwardingAddress,

            string id,

            bool isForwarding,

            bool isListening,

            string listeningAddress,

            string name,

            ImmutableArray<string> nsgIds,

            string resolverEndpointName,

            string resolverId,

            string scope,

            string self,

            string state,

            string subnetId,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            EndpointType = endpointType;
            ForwardingAddress = forwardingAddress;
            Id = id;
            IsForwarding = isForwarding;
            IsListening = isListening;
            ListeningAddress = listeningAddress;
            Name = name;
            NsgIds = nsgIds;
            ResolverEndpointName = resolverEndpointName;
            ResolverId = resolverId;
            Scope = scope;
            Self = self;
            State = state;
            SubnetId = subnetId;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
