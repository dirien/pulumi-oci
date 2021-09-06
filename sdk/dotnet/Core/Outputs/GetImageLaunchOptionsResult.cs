// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetImageLaunchOptionsResult
    {
        /// <summary>
        /// Emulation type for the boot volume.
        /// </summary>
        public readonly string BootVolumeType;
        /// <summary>
        /// Firmware used to boot VM. Select the option that matches your operating system.
        /// </summary>
        public readonly string Firmware;
        /// <summary>
        /// Whether to enable consistent volume naming feature. Defaults to false.
        /// </summary>
        public readonly bool IsConsistentVolumeNamingEnabled;
        /// <summary>
        /// Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/LaunchInstanceDetails).
        /// </summary>
        public readonly bool IsPvEncryptionInTransitEnabled;
        /// <summary>
        /// Emulation type for the physical network interface card (NIC).
        /// </summary>
        public readonly string NetworkType;
        /// <summary>
        /// Emulation type for volume.
        /// </summary>
        public readonly string RemoteDataVolumeType;

        [OutputConstructor]
        private GetImageLaunchOptionsResult(
            string bootVolumeType,

            string firmware,

            bool isConsistentVolumeNamingEnabled,

            bool isPvEncryptionInTransitEnabled,

            string networkType,

            string remoteDataVolumeType)
        {
            BootVolumeType = bootVolumeType;
            Firmware = firmware;
            IsConsistentVolumeNamingEnabled = isConsistentVolumeNamingEnabled;
            IsPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
            NetworkType = networkType;
            RemoteDataVolumeType = remoteDataVolumeType;
        }
    }
}
