// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetPublicIps
    {
        /// <summary>
        /// This data source provides the list of Public Ips in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the [PublicIp](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/PublicIp/) objects
        /// in the specified compartment. You can filter the list by using query parameters.
        /// 
        /// To list your reserved public IPs:
        ///   * Set `scope` = `REGION`  (required)
        ///   * Leave the `availabilityDomain` parameter empty
        ///   * Set `lifetime` = `RESERVED`
        /// 
        /// To list the ephemeral public IPs assigned to a regional entity such as a NAT gateway:
        ///   * Set `scope` = `REGION`  (required)
        ///   * Leave the `availabilityDomain` parameter empty
        ///   * Set `lifetime` = `EPHEMERAL`
        /// 
        /// To list the ephemeral public IPs assigned to private IPs:
        ///   * Set `scope` = `AVAILABILITY_DOMAIN` (required)
        ///   * Set the `availabilityDomain` parameter to the desired availability domain (required)
        ///   * Set `lifetime` = `EPHEMERAL`
        /// 
        /// **Note:** An ephemeral public IP assigned to a private IP
        /// is always in the same availability domain and compartment as the private IP.
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
        ///         var testPublicIps = Output.Create(Oci.Core.GetPublicIps.InvokeAsync(new Oci.Core.GetPublicIpsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Scope = @var.Public_ip_scope,
        ///             AvailabilityDomain = @var.Public_ip_availability_domain,
        ///             Lifetime = @var.Public_ip_lifetime,
        ///             PublicIpPoolId = oci_core_public_ip_pool.Test_public_ip_pool.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetPublicIpsResult> InvokeAsync(GetPublicIpsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPublicIpsResult>("oci:core/getPublicIps:getPublicIps", args ?? new GetPublicIpsArgs(), options.WithVersion());
    }


    public sealed class GetPublicIpsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public string? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetPublicIpsFilterArgs>? _filters;
        public List<Inputs.GetPublicIpsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetPublicIpsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only public IPs that match given lifetime.
        /// </summary>
        [Input("lifetime")]
        public string? Lifetime { get; set; }

        /// <summary>
        /// A filter to return only resources that belong to the given public IP pool.
        /// </summary>
        [Input("publicIpPoolId")]
        public string? PublicIpPoolId { get; set; }

        /// <summary>
        /// Whether the public IP is regional or specific to a particular availability domain.
        /// * `REGION`: The public IP exists within a region and is assigned to a regional entity (such as a [NatGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NatGateway/)), or can be assigned to a private IP in any availability domain in the region. Reserved public IPs have `scope` = `REGION`, as do ephemeral public IPs assigned to a regional entity.
        /// * `AVAILABILITY_DOMAIN`: The public IP exists within the availability domain of the entity it's assigned to, which is specified by the `availabilityDomain` property of the public IP object. Ephemeral public IPs that are assigned to private IPs have `scope` = `AVAILABILITY_DOMAIN`.
        /// </summary>
        [Input("scope", required: true)]
        public string Scope { get; set; } = null!;

        public GetPublicIpsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetPublicIpsResult
    {
        /// <summary>
        /// The public IP's availability domain. This property is set only for ephemeral public IPs that are assigned to a private IP (that is, when the `scope` of the public IP is set to AVAILABILITY_DOMAIN). The value is the availability domain of the assigned private IP.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// The OCID of the compartment containing the public IP. For an ephemeral public IP, this is the compartment of its assigned entity (which can be a private IP or a regional entity such as a NAT gateway). For a reserved public IP that is currently assigned, its compartment can be different from the assigned private IP's.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetPublicIpsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Defines when the public IP is deleted and released back to Oracle's public IP pool.
        /// * `EPHEMERAL`: The lifetime is tied to the lifetime of its assigned entity. An ephemeral public IP must always be assigned to an entity. If the assigned entity is a private IP, the ephemeral public IP is automatically deleted when the private IP is deleted, when the VNIC is terminated, or when the instance is terminated. If the assigned entity is a [NatGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NatGateway/), the ephemeral public IP is automatically deleted when the NAT gateway is terminated.
        /// * `RESERVED`: You control the public IP's lifetime. You can delete a reserved public IP whenever you like. It does not need to be assigned to a private IP at all times.
        /// </summary>
        public readonly string? Lifetime;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pool object created in the current tenancy.
        /// </summary>
        public readonly string? PublicIpPoolId;
        /// <summary>
        /// The list of public_ips.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPublicIpsPublicIpResult> PublicIps;
        /// <summary>
        /// Whether the public IP is regional or specific to a particular availability domain.
        /// * `REGION`: The public IP exists within a region and is assigned to a regional entity (such as a [NatGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NatGateway/)), or can be assigned to a private IP in any availability domain in the region. Reserved public IPs and ephemeral public IPs assigned to a regional entity have `scope` = `REGION`.
        /// * `AVAILABILITY_DOMAIN`: The public IP exists within the availability domain of the entity it's assigned to, which is specified by the `availabilityDomain` property of the public IP object. Ephemeral public IPs that are assigned to private IPs have `scope` = `AVAILABILITY_DOMAIN`.
        /// </summary>
        public readonly string Scope;

        [OutputConstructor]
        private GetPublicIpsResult(
            string? availabilityDomain,

            string compartmentId,

            ImmutableArray<Outputs.GetPublicIpsFilterResult> filters,

            string id,

            string? lifetime,

            string? publicIpPoolId,

            ImmutableArray<Outputs.GetPublicIpsPublicIpResult> publicIps,

            string scope)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            Lifetime = lifetime;
            PublicIpPoolId = publicIpPoolId;
            PublicIps = publicIps;
            Scope = scope;
        }
    }
}
