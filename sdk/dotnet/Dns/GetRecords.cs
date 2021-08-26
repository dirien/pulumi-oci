// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns
{
    public static class GetRecords
    {
        public static Task<GetRecordsResult> InvokeAsync(GetRecordsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetRecordsResult>("oci:dns/getRecords:getRecords", args ?? new GetRecordsArgs(), options.WithVersion());
    }


    public sealed class GetRecordsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment the resource belongs to.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// Search by domain. Will match any record whose domain (case-insensitive) equals the provided value.
        /// </summary>
        [Input("domain")]
        public string? Domain { get; set; }

        /// <summary>
        /// Search by domain. Will match any record whose domain (case-insensitive) contains the provided value.
        /// </summary>
        [Input("domainContains")]
        public string? DomainContains { get; set; }

        [Input("filters")]
        private List<Inputs.GetRecordsFilterArgs>? _filters;
        public List<Inputs.GetRecordsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetRecordsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
        /// </summary>
        [Input("rtype")]
        public string? Rtype { get; set; }

        /// <summary>
        /// The field by which to sort records. Allowed values are: domain|rtype|ttl
        /// </summary>
        [Input("sortBy")]
        public string? SortBy { get; set; }

        /// <summary>
        /// The order to sort the resources. Allowed values are: ASC|DESC
        /// </summary>
        [Input("sortOrder")]
        public string? SortOrder { get; set; }

        /// <summary>
        /// The name or OCID of the target zone.
        /// </summary>
        [Input("zoneNameOrId", required: true)]
        public string ZoneNameOrId { get; set; } = null!;

        /// <summary>
        /// The version of the zone for which data is requested.
        /// </summary>
        [Input("zoneVersion")]
        public string? ZoneVersion { get; set; }

        public GetRecordsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetRecordsResult
    {
        public readonly string? CompartmentId;
        /// <summary>
        /// The fully qualified domain name where the record can be located.
        /// </summary>
        public readonly string? Domain;
        public readonly string? DomainContains;
        public readonly ImmutableArray<Outputs.GetRecordsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of records.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRecordsRecordResult> Records;
        /// <summary>
        /// The canonical name for the record's type, such as A or CNAME. For more information, see [Resource Record (RR) TYPEs](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4).
        /// </summary>
        public readonly string? Rtype;
        public readonly string? SortBy;
        public readonly string? SortOrder;
        /// <summary>
        /// The name or OCID of the target zone.
        /// </summary>
        public readonly string ZoneNameOrId;
        public readonly string? ZoneVersion;

        [OutputConstructor]
        private GetRecordsResult(
            string? compartmentId,

            string? domain,

            string? domainContains,

            ImmutableArray<Outputs.GetRecordsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetRecordsRecordResult> records,

            string? rtype,

            string? sortBy,

            string? sortOrder,

            string zoneNameOrId,

            string? zoneVersion)
        {
            CompartmentId = compartmentId;
            Domain = domain;
            DomainContains = domainContains;
            Filters = filters;
            Id = id;
            Records = records;
            Rtype = rtype;
            SortBy = sortBy;
            SortOrder = sortOrder;
            ZoneNameOrId = zoneNameOrId;
            ZoneVersion = zoneVersion;
        }
    }
}