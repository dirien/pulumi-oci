// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetAutonomousDatabasesAutonomousDatabaseConnectionStringsResult
    {
        /// <summary>
        /// Returns all connection strings that can be used to connect to the Autonomous Database. For more information, please see [Predefined Database Service Names for Autonomous Transaction Processing](https://docs.oracle.com/en/cloud/paas/atp-cloud/atpug/connect-predefined.html#GUID-9747539B-FD46-44F1-8FF8-F5AC650F15BE)
        /// </summary>
        public readonly ImmutableDictionary<string, object> AllConnectionStrings;
        /// <summary>
        /// The database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
        /// </summary>
        public readonly string Dedicated;
        /// <summary>
        /// The High database service provides the highest level of resources to each SQL statement resulting in the highest performance, but supports the fewest number of concurrent SQL statements.
        /// </summary>
        public readonly string High;
        /// <summary>
        /// The Low database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
        /// </summary>
        public readonly string Low;
        /// <summary>
        /// The Medium database service provides a lower level of resources to each SQL statement potentially resulting a lower level of performance, but supports more concurrent SQL statements.
        /// </summary>
        public readonly string Medium;

        [OutputConstructor]
        private GetAutonomousDatabasesAutonomousDatabaseConnectionStringsResult(
            ImmutableDictionary<string, object> allConnectionStrings,

            string dedicated,

            string high,

            string low,

            string medium)
        {
            AllConnectionStrings = allConnectionStrings;
            Dedicated = dedicated;
            High = high;
            Low = low;
            Medium = medium;
        }
    }
}
