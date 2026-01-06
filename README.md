# OpenStack Cinder replicated volume driver

This driver utilizes Openstack Cinder Replication API to ensure high availability and rapid recovery of Cinder volumes in the event of a failure. Openstack Cinder Replication provides synchronous, nea  synchronous or assynchronous data replication between the source and replicated volumes, guaranteeing data integrity and minimal recovery time. Crucially, this allows you to leverage the driver for applications requiring low-latency block storage, potentially replacing Ceph where minimal latency is paramount. For detailed information on configuring and using Openstack Cinder Replication, please refer to the official OpenStack documentation: https://docs.openstack.org/cinder/latest/contributor/replication.html

# Features
- Creates a fault-tolerant OpenStack Cinder volume service with data replication on backup hosts
- Switches volumes to a backup storage node in the case of a primary node failure
- Freezes volumes lifecycle management while maintaining data access during a disaster
- Restores to the original state, ensuring operations on the backup device as soon as it becomes available
- Thaws volumes lifecycle management as soon as replicated storages becomes available
- Thin and thick volumes
- Create, delete, mount, and unmount volume
- Create, view, and delete volume
- Create a volume from a volume snapshot
- Copy image to a volume
- Copy a volume to image
- Clone volume
- Migrating a volume between storage hosts
- Retyping volume
- Volime resizing
- Compatibility with Python 3

# Driver installation

Get source code:
```
git clone https://gitlab.com/ovtsolutions/ev3.git 
```

```
sudo apt install lvm2 targetcli-fb python3-rtslib-fb drbd-utils -y
sudo cp ev3/etc/cinder/rootwrap.d/ev3.filters /etc/cinder/rootwrap.d/
sudo cp -r ev3/cinder/volume/drivers/ovt /usr/lib/python3/dist-packages/cinder/volume/drivers/
```

# Openstack Cinder block device type with replication support creation
```
openstack volume type create RBS --property volume_backend_name='ev3' --property replication_enabled='<is> True'
```

# Example of Cinder volume configuration
```
[DEFAULT]
...
enabled_backends = RBS

[RBS]
target_helper=lioadm
target_protocol=iscsi 
target_ip_address=10.0.251.21
target_secondary_ip_addresses=10.0.252.21

volume_backend_name=ev3
volume_driver = cinder.volume.drivers.ovt.ev3.ReplicatedVolumeDriver
volume_group=volumes

# storage backend id
backend_id=hci-0001@RBS
# storage API address
backend_ip=10.0.10.21
# storage API port
backend_port=7000

# unique replication internal secret sharted between replicated hosts and used in web requests 
# use your unique value...
replication_internal_secret = 4abcfe3b-367f-477d-89bd-283c4382e5f6

# available modes
# async : write completion is determined when data
# semi-sync: write completion is determined when data is written to the local disk and the local TOP transmission buffer
# full-sync: write completion is determined when data is written to both the local disk and the remote disk (default mode)
replication_mode = full-sync

#replication_resync_rate = 100
#replication_starting_port = 7001
replication_device = backend_id:hci-0002@RBS,ip:10.0.10.22,port:7000,volume_group:volumes
```
# Usage
Failover policy creation. The backup host (in the example, hci-0002@RBS) will be shut down and marked as failed-over, while the volumes on them will remain accessible:
```
openstack volume service list --long
+------------------+--------------+------+---------+-------+----------------------------+---------------------------------------------------------------+
| Binary           | Host         | Zone | Status  | State | Updated At                 | Disabled Reason                                               |
+------------------+--------------+------+---------+-------+----------------------------+---------------------------------------------------------------+
| cinder-scheduler | hci-0001     | AZ01 | enabled | up    | 2025-11-18T12:41:31.000000 | None                                                          |
| cinder-scheduler | hci-0002     | AZ01 | enabled | up    | 2025-11-18T12:41:33.000000 | None                                                          |
| cinder-volume    | hci-0001@RBS | AZ01 | enabled | up    | 2025-11-18T12:41:27.000000 | None                                                          |
| cinder-volume    | hci-0002@RBS | AZ01 | enabled | up    | 2025-11-18T12:41:25.000000 | None                                                          |
+------------------+--------------+------+---------+-------+----------------------------+---------------------------------------------------------------+

cinder failover-host hci-0002@RBS --backend_id hci-0001@RBS

openstack volume service list --long
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| Binary           | Host         | Zone | Status   | State | Updated At                 | Disabled Reason                                               |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| cinder-scheduler | hci-0001     | AZ01 | enabled  | up    | 2025-11-18T12:42:51.000000 | None                                                          |
| cinder-scheduler | hci-0002     | AZ01 | enabled  | up    | 2025-11-18T12:42:53.000000 | None                                                          |
| cinder-volume    | hci-0001@RBS | AZ01 | enabled  | up    | 2025-11-18T12:42:28.000000 | None                                                          |
| cinder-volume    | hci-0002@RBS | AZ01 | disabled | up    | 2025-11-18T12:42:24.000000 | failed-over                                                   |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
```
Replicated device block creation
```
openstack volume type list
+--------------------------------------+-------------+-----------+
| ID                                   | Name        | Is Public |
+--------------------------------------+-------------+-----------+
| 387e6744-52ba-441b-8848-969ff8541885 | RBS         | True      |
| 03dffb4d-58bc-438b-84ed-a57c93e6d177 | __DEFAULT__ | False     |
+--------------------------------------+-------------+-----------+

openstack volume create --type RBS --size 10 replicated
+---------------------+--------------------------------------+
| Field               | Value                                |
+---------------------+--------------------------------------+
| attachments         | []                                   |
| availability_zone   | AZ01                                 |
| bootable            | false                                |
| consistencygroup_id | None                                 |
| created_at          | 2025-11-18T12:49:41.198320           |
| description         | None                                 |
| encrypted           | False                                |
| group_id            | None                                 |
| id                  | caaa7f09-c8ca-4dc9-9205-2bbaed378482 |
| migration_status    | None                                 |
| multiattach         | False                                |
| name                | replicated                           |
| properties          |                                      |
| provider_id         | None                                 |
| replication_status  | None                                 |
| size                | 10                                   |
| snapshot_id         | None                                 |
| source_volid        | None                                 |
| status              | creating                             |
| type                | RBS                                  |
| updated_at          | None                                 |
| user_id             | 993d0e88b013438fb2b8ce6e4e77459b     |
+---------------------+--------------------------------------+

openstack volume show caaa7f09-c8ca-4dc9-9205-2bbaed378482
+--------------------------------+--------------------------------------+
| Field                          | Value                                |
+--------------------------------+--------------------------------------+
| attachments                    | []                                   |
| availability_zone              | AZ01                                 |
| bootable                       | false                                |
| consistencygroup_id            | None                                 |
| created_at                     | 2025-11-18T12:49:41.000000           |
| description                    | None                                 |
| encrypted                      | False                                |
| group_id                       | None                                 |
| id                             | caaa7f09-c8ca-4dc9-9205-2bbaed378482 |
| migration_status               | None                                 |
| multiattach                    | False                                |
| name                           | replicated                           |
| os-vol-host-attr:host          | hci-0001@RBS#ev3                     |
| os-vol-mig-status-attr:migstat | None                                 |
| os-vol-mig-status-attr:name_id | None                                 |
| os-vol-tenant-attr:tenant_id   | db06b1a84e6544aabe74683fe87b084a     |
| properties                     |                                      |
| provider_id                    | None                                 |
| replication_status             | enabled                              |
| size                           | 10                                   |
| snapshot_id                    | None                                 |
| source_volid                   | None                                 |
| status                         | available                            |
| type                           | RBS                                  |
| updated_at                     | 2025-11-18T12:49:41.000000           |
| user_id                        | 993d0e88b013438fb2b8ce6e4e77459b     |
+--------------------------------+--------------------------------------+
```
Move failover node to the primary role and freeze for changies when an accident is occured
```
openstack volume service list --long
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| Binary           | Host         | Zone | Status   | State | Updated At                 | Disabled Reason                                               |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| cinder-scheduler | hci-0001     | AZ01 | enabled  | up    | 2025-11-18T12:45:31.000000 | None                                                          |
| cinder-scheduler | hci-0002     | AZ01 | enabled  | up    | 2025-11-18T12:45:33.000000 | None                                                          |
| cinder-volume    | hci-0001@RBS | AZ01 | enabled  | down  | 2025-11-18T12:45:27.000000 | None                                                          |
| cinder-volume    | hci-0002@RBS | AZ01 | disabled | up    | 2025-11-18T12:45:24.000000 | failed-over                                                   |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+

cinder failover-host hci-0002@RBS --backend_id default
cinder freeze-host hci-0002@RBS

openstack volume service list --long
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| Binary           | Host         | Zone | Status   | State | Updated At                 | Disabled Reason                                               |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| cinder-scheduler | hci-0001     | AZ01 | enabled  | up    | 2025-11-18T12:46:22.000000 | None                                                          |
| cinder-scheduler | hci-0002     | AZ01 | enabled  | up    | 2025-11-18T12:46:34.000000 | None                                                          |
| cinder-volume    | hci-0001@RBS | AZ01 | enabled  | down  | 2025-11-18T12:46:37.000000 | None                                                          |
| cinder-volume    | hci-0002@RBS | AZ01 | disabled | up    | 2025-11-18T12:46:34.000000 | frozen                                                        |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
```
User access to the recovery volume. The volume must be detached and attached again.
```
openstack volume show caaa7f09-c8ca-4dc9-9205-2bbaed378482
+--------------------------------+--------------------------------------+
| Field                          | Value                                |
+--------------------------------+--------------------------------------+
| attachments                    | []                                   |
| availability_zone              | AZ01                                 |
| bootable                       | false                                |
| consistencygroup_id            | None                                 |
| created_at                     | 2025-11-18T12:49:41.000000           |
| description                    | None                                 |
| encrypted                      | False                                |
| group_id                       | None                                 |
| id                             | caaa7f09-c8ca-4dc9-9205-2bbaed378482 |
| migration_status               | None                                 |
| multiattach                    | False                                |
| name                           | replicated                           |
| os-vol-host-attr:host          | hci-0002@RBS#ev3                     |
| os-vol-mig-status-attr:migstat | None                                 |
| os-vol-mig-status-attr:name_id | None                                 |
| os-vol-tenant-attr:tenant_id   | db06b1a84e6544aabe74683fe87b084a     |
| properties                     |                                      |
| provider_id                    | None                                 |
| replication_status             | enabled                              |
| size                           | 10                                   |
| snapshot_id                    | None                                 |
| source_volid                   | None                                 |
| status                         | available                            |
| type                           | RBS                                  |
| updated_at                     | 2025-11-18T12:49:41.000000           |
| user_id                        | 993d0e88b013438fb2b8ce6e4e77459b     |
+--------------------------------+--------------------------------------+
```
Recovering from a failed storage node
```
openstack volume service list --long
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| Binary           | Host         | Zone | Status   | State | Updated At                 | Disabled Reason                                               |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| cinder-scheduler | hci-0001     | AZ01 | enabled  | up    | 2025-11-18T12:47:18.000000 | None                                                          |
| cinder-scheduler | hci-0002     | AZ01 | enabled  | up    | 2025-11-18T12:47:23.000000 | None                                                          |
| cinder-volume    | hci-0001@RBS | AZ01 | enabled  | up    | 2025-11-18T12:47:31.000000 | None                                                          |
| cinder-volume    | hci-0002@RBS | AZ01 | disabled | up    | 2025-11-18T12:47:23.000000 | frozen                                                        |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
cinder thaw-host hci-0002@RBS
cinder failover-host hci-0001@RBS --backend_id hci-0002@RBS

openstack volume service list --long
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| Binary           | Host         | Zone | Status   | State | Updated At                 | Disabled Reason                                               |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| cinder-scheduler | hci-0001     | AZ01 | enabled  | up    | 2025-11-18T12:47:48.000000 | None                                                          |
| cinder-scheduler | hci-0002     | AZ01 | enabled  | up    | 2025-11-18T12:47:53.000000 | None                                                          |
| cinder-volume    | hci-0001@RBS | AZ01 | disabled | up    | 2025-11-18T12:47:54.000000 | failed-over                                                   |
| cinder-volume    | hci-0002@RBS | AZ01 | enabled  | up    | 2025-11-18T12:47:55.000000 | None                                                          |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
```
