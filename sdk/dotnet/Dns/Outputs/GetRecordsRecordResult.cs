// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns.Outputs
{

    [OutputType]
    public sealed class GetRecordsRecordResult
    {
        /// <summary>
        /// The OCID of the compartment the resource belongs to.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// Search by domain. Will match any record whose domain (case-insensitive) equals the provided value.
        /// </summary>
        public readonly string Domain;
        /// <summary>
        /// A Boolean flag indicating whether or not parts of the record are unable to be explicitly managed.
        /// </summary>
        public readonly bool IsProtected;
        /// <summary>
        /// The record's data, as whitespace-delimited tokens in type-specific presentation format. All RDATA is normalized and the returned presentation of your RDATA may differ from its initial input. For more information about RDATA, see [Supported DNS Resource Record Types](https://docs.cloud.oracle.com/iaas/Content/DNS/Reference/supporteddnsresource.htm)
        /// </summary>
        public readonly string? Rdata;
        /// <summary>
        /// A unique identifier for the record within its zone.
        /// </summary>
        public readonly string RecordHash;
        /// <summary>
        /// The latest version of the record's zone in which its RRSet differs from the preceding version.
        /// </summary>
        public readonly string RrsetVersion;
        /// <summary>
        /// Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
        /// </summary>
        public readonly string Rtype;
        /// <summary>
        /// The Time To Live for the record, in seconds.
        /// </summary>
        public readonly int? Ttl;
        /// <summary>
        /// The name or OCID of the target zone.
        /// </summary>
        public readonly string ZoneNameOrId;

        [OutputConstructor]
        private GetRecordsRecordResult(
            string? compartmentId,

            string domain,

            bool isProtected,

            string? rdata,

            string recordHash,

            string rrsetVersion,

            string rtype,

            int? ttl,

            string zoneNameOrId)
        {
            CompartmentId = compartmentId;
            Domain = domain;
            IsProtected = isProtected;
            Rdata = rdata;
            RecordHash = recordHash;
            RrsetVersion = rrsetVersion;
            Rtype = rtype;
            Ttl = ttl;
            ZoneNameOrId = zoneNameOrId;
        }
    }
}
