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
    public sealed class GetExadataInfrastructureMaintenanceWindowResult
    {
        /// <summary>
        /// Days during the week when maintenance should be performed.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExadataInfrastructureMaintenanceWindowDaysOfWeekResult> DaysOfWeeks;
        /// <summary>
        /// The window of hours during the day when maintenance should be performed. The window is a 4 hour slot. Valid values are
        /// * 0 - represents time slot 0:00 - 3:59 UTC - 4 - represents time slot 4:00 - 7:59 UTC - 8 - represents time slot 8:00 - 11:59 UTC - 12 - represents time slot 12:00 - 15:59 UTC - 16 - represents time slot 16:00 - 19:59 UTC - 20 - represents time slot 20:00 - 23:59 UTC
        /// </summary>
        public readonly ImmutableArray<int> HoursOfDays;
        /// <summary>
        /// Lead time window allows user to set a lead time to prepare for a down time. The lead time is in weeks and valid value is between 1 to 4.
        /// </summary>
        public readonly int LeadTimeInWeeks;
        /// <summary>
        /// Months during the year when maintenance should be performed.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExadataInfrastructureMaintenanceWindowMonthResult> Months;
        /// <summary>
        /// The maintenance window scheduling preference.
        /// </summary>
        public readonly string Preference;
        /// <summary>
        /// Weeks during the month when maintenance should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow maintenance during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Maintenance cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and hoursOfDay parameters to allow you to specify specific days of the week and hours that maintenance will be performed.
        /// </summary>
        public readonly ImmutableArray<int> WeeksOfMonths;

        [OutputConstructor]
        private GetExadataInfrastructureMaintenanceWindowResult(
            ImmutableArray<Outputs.GetExadataInfrastructureMaintenanceWindowDaysOfWeekResult> daysOfWeeks,

            ImmutableArray<int> hoursOfDays,

            int leadTimeInWeeks,

            ImmutableArray<Outputs.GetExadataInfrastructureMaintenanceWindowMonthResult> months,

            string preference,

            ImmutableArray<int> weeksOfMonths)
        {
            DaysOfWeeks = daysOfWeeks;
            HoursOfDays = hoursOfDays;
            LeadTimeInWeeks = leadTimeInWeeks;
            Months = months;
            Preference = preference;
            WeeksOfMonths = weeksOfMonths;
        }
    }
}
