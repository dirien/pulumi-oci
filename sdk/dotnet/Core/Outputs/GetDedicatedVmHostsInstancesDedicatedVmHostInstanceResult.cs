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
    public sealed class GetDedicatedVmHostsInstancesDedicatedVmHostInstanceResult
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The OCID of the virtual machine instance.
        /// </summary>
        public readonly string InstanceId;
        /// <summary>
        /// The shape of the VM instance.
        /// </summary>
        public readonly string Shape;
        /// <summary>
        /// The date and time the virtual machine instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetDedicatedVmHostsInstancesDedicatedVmHostInstanceResult(
            string availabilityDomain,

            string compartmentId,

            string instanceId,

            string shape,

            string timeCreated)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            InstanceId = instanceId;
            Shape = shape;
            TimeCreated = timeCreated;
        }
    }
}
