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
    public sealed class ExadataInfrastructureContact
    {
        /// <summary>
        /// (Updatable) The email for the Exadata Infrastructure contact.
        /// </summary>
        public readonly string Email;
        /// <summary>
        /// (Updatable) If `true`, this Exadata Infrastructure contact is a valid My Oracle Support (MOS) contact. If `false`, this Exadata Infrastructure contact is not a valid MOS contact.
        /// </summary>
        public readonly bool? IsContactMosValidated;
        /// <summary>
        /// (Updatable) If `true`, this Exadata Infrastructure contact is a primary contact. If `false`, this Exadata Infrastructure is a secondary contact.
        /// </summary>
        public readonly bool IsPrimary;
        /// <summary>
        /// (Updatable) Name of the month of the year.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// (Updatable) The phone number for the Exadata Infrastructure contact.
        /// </summary>
        public readonly string? PhoneNumber;

        [OutputConstructor]
        private ExadataInfrastructureContact(
            string email,

            bool? isContactMosValidated,

            bool isPrimary,

            string name,

            string? phoneNumber)
        {
            Email = email;
            IsContactMosValidated = isContactMosValidated;
            IsPrimary = isPrimary;
            Name = name;
            PhoneNumber = phoneNumber;
        }
    }
}
