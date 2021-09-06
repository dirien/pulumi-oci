// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package mysql

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Mysql Backups in Oracle Cloud Infrastructure MySQL Database service.
//
// Get a list of DB System backups.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/mysql"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := oci_mysql_mysql_backup.Test_backup.Id
// 		opt1 := _var.Mysql_backup_creation_type
// 		opt2 := oci_mysql_mysql_db_system.Test_db_system.Id
// 		opt3 := _var.Mysql_backup_display_name
// 		opt4 := _var.Mysql_backup_state
// 		_, err := mysql.GetMysqlBackups(ctx, &mysql.GetMysqlBackupsArgs{
// 			CompartmentId: _var.Compartment_id,
// 			BackupId:      &opt0,
// 			CreationType:  &opt1,
// 			DbSystemId:    &opt2,
// 			DisplayName:   &opt3,
// 			State:         &opt4,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetMysqlBackups(ctx *pulumi.Context, args *GetMysqlBackupsArgs, opts ...pulumi.InvokeOption) (*GetMysqlBackupsResult, error) {
	var rv GetMysqlBackupsResult
	err := ctx.Invoke("oci:mysql/getMysqlBackups:getMysqlBackups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMysqlBackups.
type GetMysqlBackupsArgs struct {
	// Backup OCID
	BackupId *string `pulumi:"backupId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// Backup creationType
	CreationType *string `pulumi:"creationType"`
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId *string `pulumi:"dbSystemId"`
	// A filter to return only the resource matching the given display name exactly.
	DisplayName *string                 `pulumi:"displayName"`
	Filters     []GetMysqlBackupsFilter `pulumi:"filters"`
	// Backup Lifecycle State
	State *string `pulumi:"state"`
}

// A collection of values returned by getMysqlBackups.
type GetMysqlBackupsResult struct {
	BackupId *string `pulumi:"backupId"`
	// The list of backups.
	Backups []GetMysqlBackupsBackup `pulumi:"backups"`
	// The OCID of the compartment the DB System belongs in.
	CompartmentId string `pulumi:"compartmentId"`
	// If the backup was created automatically, or by a manual request.
	CreationType *string `pulumi:"creationType"`
	// The OCID of the DB System the backup is associated with.
	DbSystemId *string `pulumi:"dbSystemId"`
	// A user-supplied display name for the backup.
	DisplayName *string                 `pulumi:"displayName"`
	Filters     []GetMysqlBackupsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The state of the backup.
	State *string `pulumi:"state"`
}
