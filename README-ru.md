# Драйвер реплицированных блочных устройств (томов) OpenStack Cinder

Этот драйвер использует API репликации Openstack Cinder для обеспечения высокой доступности и быстрого восстановления томов Cinder в случае сбоя. Репликация Openstack Cinder обеспечивает синхронную, почти синхронную или асинхронную репликацию данных между исходным и реплицируемыми томами, гарантируя целостность данных и минимальное время восстановления. Что особенно важно, это позволяет использовать драйвер для приложений, требующих блочного хранилища с низкой задержкой, потенциально заменяя Ceph там, где минимальная задержка имеет первостепенное значение. Для получения подробной информации о настройке и использовании репликации Openstack Cinder обратитесь к официальной документации OpenStack: https://docs.openstack.org/cinder/latest/contributor/replication.html

## Возможности
- Создание отказоустойчивого ресурса/сервиса хранения Openstack Cinder с репликацией данных на failover хосты. 
- Переключение томов блочных устройств на один из резервных узлов хранения, в случае сбоя основного узла хранения.
- "Заморозка" (freeze) - блокировка операций управления жизненным циклом блочных устройств с сохранением доступа к данным на момент аварии.
- Возврат к исходному состоянию, обеспечивающий выполнение операций на основном сервере, как только он станет доступным/работоспособным.
- "Разморозка" (thaw) – полная разблокировка операций управления жизненным циклом блочного устройства.
- Тонкие и толстые тома
- Создание, удаление, подключение и отключение томов.
- Создание, просмотр и удаление снимков томов.
- Создание тома из снимка тома.
- Копирование образа виртуальной машины в том.
- Копирование тома в образ виртуальной машины.
- Клонирование тома. 
- Миграция тома между хостами хранения 
- Изменение типа блочного устройства (retyping)
- Изменение размера тома
- Совместимость с Python 3.9 и 3.11

## Установка драйвера 
HCI ОТВ эв3
```

git clone https://github.com/ovtsolutions/ev3.git

sudo cp ev3/etc/cinder/rootwrap.d/ev3.filters  /opt/hci/etc/cinder/rootwrap.d/
sudo cp -r ev3/cinder/volume/drivers/ovt /opt/hci/lib/python3.11/dist-packages/cinder/volume/drivers/
```

Debian/Ubuntu
```
git clone https://github.com/ovtsolutions/ev3.git 

sudo apt install lvm2 targetcli-fb python3-rtslib-fb drbd-utils -y

sudo cp ev3/etc/cinder/rootwrap.d/ev3.filters /etc/cinder/rootwrap.d/
sudo cp -r ev3/cinder/volume/drivers/ovt /usr/lib/python3/dist-packages/cinder/volume/drivers/
```
РЕД ОС 8.0
```
git clone https://github.com/ovtsolutions/ev3.git 

sudo dnf install lvm2 targetcli-fb python3-rtslib-fb drbd-utils

sudo cp ev3/etc/cinder/rootwrap.d/ev3.filters /etc/cinder/rootwrap.d/
sudo cp -r ev3/cinder/volume/drivers/ovt /usr/lib/python3/dist-packages/cinder/volume/drivers/
```

## Создание типа блочных устройств Openstack Cinder c поддержкой репликации 
```
openstack volume type create RBS --property volume_backend_name='ev3' --property replication_enabled='<is> True'
```

## Пример настройки драйвера Openstack Cinder (две копии данных)
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

### Использование
Формирование политики отказоустойчивости. Резервные хост cinder-volume (в примере hci-0002@RBS) будет отключен и помечен как failed-over, а тома на нём остаются доступными:
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
| cinder-volume    | hci-0001@RBS | AZ01 | enabled  | up    | 2025-11-18T12:42:28.000000 |                                                               |
| cinder-volume    | hci-0002@RBS | AZ01 | disabled | up    | 2025-11-18T12:42:24.000000 | failed-over                                                   |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
```
Создание реплицируемого блочного устройства.
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

Перевод одного из узлов хранения к primary роли, при аварии
```
openstack volume service list --long
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| Binary           | Host         | Zone | Status   | State | Updated At                 | Disabled Reason                                               |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| cinder-scheduler | hci-0001     | AZ01 | enabled  | up    | 2025-11-18T12:45:31.000000 | None                                                          |
| cinder-scheduler | hci-0002     | AZ01 | enabled  | up    | 2025-11-18T12:45:33.000000 | None                                                          |
| cinder-volume    | hci-0001@RBS | AZ01 | enabled  | down  | 2025-11-18T12:45:27.000000 |                                                               |
| cinder-volume    | hci-0002@RBS | AZ01 | disabled | up    | 2025-11-18T12:45:24.000000 | failed-over                                                   |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+

cinder failover-host hci-0002@RBS --backend_id default
cinder freeze-host hci-0002@RBS

cinder-manage volume update_host --currenthost hci-0001@RBS#ev3 --newhost hci-0002@RBS#ev3

openstack volume service list --long
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| Binary           | Host         | Zone | Status   | State | Updated At                 | Disabled Reason                                               |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| cinder-scheduler | hci-0001     | AZ01 | enabled  | up    | 2025-11-18T12:46:22.000000 | None                                                          |
| cinder-scheduler | hci-0002     | AZ01 | enabled  | up    | 2025-11-18T12:46:34.000000 | None                                                          |
| cinder-volume    | hci-0001@RBS | AZ01 | enabled  | down  | 2025-11-18T12:46:37.000000 |                                                               |
| cinder-volume    | hci-0002@RBS | AZ01 | disabled | up    | 2025-11-18T12:46:34.000000 | frozen                                                        |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
```

Пользователь получает доступ к тому восстановления
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
Восстановление после сбоя аварийного узла хранения
```
openstack volume service list --long
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| Binary           | Host         | Zone | Status   | State | Updated At                 | Disabled Reason                                               |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
| cinder-scheduler | hci-0001     | AZ01 | enabled  | up    | 2025-11-18T12:47:18.000000 | None                                                          |
| cinder-scheduler | hci-0002     | AZ01 | enabled  | up    | 2025-11-18T12:47:23.000000 | None                                                          |
| cinder-volume    | hci-0001@RBS | AZ01 | enabled  | up    | 2025-11-18T12:47:31.000000 |                                                               |
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
| cinder-volume    | hci-0002@RBS | AZ01 | enabled  | up    | 2025-11-18T12:47:55.000000 |                                                               |
+------------------+--------------+------+----------+-------+----------------------------+---------------------------------------------------------------+
```
## Лицензия
Apache-2.0 license
