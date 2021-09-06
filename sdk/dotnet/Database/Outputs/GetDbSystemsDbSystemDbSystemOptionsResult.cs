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
    public sealed class GetDbSystemsDbSystemDbSystemOptionsResult
    {
        /// <summary>
        /// The storage option used in DB system. ASM - Automatic storage management LVM - Logical Volume management
        /// </summary>
        public readonly string StorageManagement;

        [OutputConstructor]
        private GetDbSystemsDbSystemDbSystemOptionsResult(string storageManagement)
        {
            StorageManagement = storageManagement;
        }
    }
}
