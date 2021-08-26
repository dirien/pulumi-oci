// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Bds.Outputs
{

    [OutputType]
    public sealed class GetBdsInstanceClusterDetailsResult
    {
        /// <summary>
        /// The URL of Ambari
        /// </summary>
        public readonly string AmbariUrl;
        /// <summary>
        /// Cloud SQL cell version.
        /// </summary>
        public readonly string BdCellVersion;
        /// <summary>
        /// BDA version installed in the cluster
        /// </summary>
        public readonly string BdaVersion;
        /// <summary>
        /// Big Data Manager version installed in the cluster.
        /// </summary>
        public readonly string BdmVersion;
        /// <summary>
        /// Big Data Service version installed in the cluster.
        /// </summary>
        public readonly string BdsVersion;
        /// <summary>
        /// The URL of Big Data Manager.
        /// </summary>
        public readonly string BigDataManagerUrl;
        /// <summary>
        /// The URL of Cloudera Manager
        /// </summary>
        public readonly string ClouderaManagerUrl;
        /// <summary>
        /// Big Data SQL version.
        /// </summary>
        public readonly string CsqlCellVersion;
        /// <summary>
        /// Cloud SQL query server database version.
        /// </summary>
        public readonly string DbVersion;
        /// <summary>
        /// The URL of the Hue server.
        /// </summary>
        public readonly string HueServerUrl;
        /// <summary>
        /// Oracle Linux version installed in the cluster.
        /// </summary>
        public readonly string OsVersion;
        /// <summary>
        /// The time the cluster was created, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the cluster was automatically or manually refreshed, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        public readonly string TimeRefreshed;

        [OutputConstructor]
        private GetBdsInstanceClusterDetailsResult(
            string ambariUrl,

            string bdCellVersion,

            string bdaVersion,

            string bdmVersion,

            string bdsVersion,

            string bigDataManagerUrl,

            string clouderaManagerUrl,

            string csqlCellVersion,

            string dbVersion,

            string hueServerUrl,

            string osVersion,

            string timeCreated,

            string timeRefreshed)
        {
            AmbariUrl = ambariUrl;
            BdCellVersion = bdCellVersion;
            BdaVersion = bdaVersion;
            BdmVersion = bdmVersion;
            BdsVersion = bdsVersion;
            BigDataManagerUrl = bigDataManagerUrl;
            ClouderaManagerUrl = clouderaManagerUrl;
            CsqlCellVersion = csqlCellVersion;
            DbVersion = dbVersion;
            HueServerUrl = hueServerUrl;
            OsVersion = osVersion;
            TimeCreated = timeCreated;
            TimeRefreshed = timeRefreshed;
        }
    }
}
