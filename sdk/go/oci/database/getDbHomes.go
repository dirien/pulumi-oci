// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Db Homes in Oracle Cloud Infrastructure Database service.
//
// Lists the Database Homes in the specified DB system and compartment. A Database Home is a directory where Oracle Database software is installed.
func GetDbHomes(ctx *pulumi.Context, args *GetDbHomesArgs, opts ...pulumi.InvokeOption) (*GetDbHomesResult, error) {
	var rv GetDbHomesResult
	err := ctx.Invoke("oci:database/getDbHomes:getDbHomes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDbHomes.
type GetDbHomesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup. Specify a backupId to list only the DB systems or DB homes that support creating a database using this backup in this compartment.
	BackupId *string `pulumi:"backupId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). If provided, filters the results to the set of database versions which are supported for the DB system.
	DbSystemId *string `pulumi:"dbSystemId"`
	// A filter to return only DB Homes that match the specified dbVersion.
	DbVersion *string `pulumi:"dbVersion"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string            `pulumi:"displayName"`
	Filters     []GetDbHomesFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
	VmClusterId *string `pulumi:"vmClusterId"`
}

// A collection of values returned by getDbHomes.
type GetDbHomesResult struct {
	BackupId *string `pulumi:"backupId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of db_homes.
	DbHomes []GetDbHomesDbHome `pulumi:"dbHomes"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
	DbSystemId *string `pulumi:"dbSystemId"`
	// The Oracle Database version.
	DbVersion *string `pulumi:"dbVersion"`
	// The user-provided name for the Database Home. The name does not need to be unique.
	DisplayName *string            `pulumi:"displayName"`
	Filters     []GetDbHomesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the Database Home.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
	VmClusterId *string `pulumi:"vmClusterId"`
}
