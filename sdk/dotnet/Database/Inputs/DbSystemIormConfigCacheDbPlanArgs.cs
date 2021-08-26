// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class DbSystemIormConfigCacheDbPlanArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The display name of the database to be created from the backup. It must begin with an alphabetic character and can contain a maximum of eight alphanumeric characters. Special characters are not permitted.
        /// </summary>
        [Input("dbName")]
        public Input<string>? DbName { get; set; }

        /// <summary>
        /// The flash cache limit for this database. This value is internally configured based on the share value assigned to the database.
        /// </summary>
        [Input("flashCacheLimit")]
        public Input<string>? FlashCacheLimit { get; set; }

        /// <summary>
        /// The relative priority of this database.
        /// </summary>
        [Input("share")]
        public Input<int>? Share { get; set; }

        public DbSystemIormConfigCacheDbPlanArgs()
        {
        }
    }
}
