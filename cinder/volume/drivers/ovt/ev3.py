# Copyright (c) 2021-2025 OVT LLC, https://www.ovtsolutions.ru
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Driver for servers running replicated volumes.
"""

import os
import threading

import six
import json
import fnmatch
import requests
import datetime
import hmac
import hashlib

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log as logging
from threading import Thread

from cinder.i18n import _
from cinder import interface
from cinder import utils
from cinder import exception
from cinder import coordination
from cinder.objects import fields
from cinder.volume.drivers.lvm import LVMVolumeDriver
from webob import Request, Response
from wsgiref.simple_server import make_server


import cinder.volume.drivers.ovt.resources as ev3_res

LOG = logging.getLogger(__name__)

replication_opts = [
    cfg.StrOpt('backend_ip',
               default='127.0.0.1',
               help='The address on which this storage server will listen for client requests'),
    cfg.IntOpt('backend_port',
               default=7000,
               help='The port on which this storage server will listen for client requests'),
    cfg.StrOpt('backend_id',
               default='localhost',
               help='Unique identifier of the current node that will be used for replication.'),
    cfg.StrOpt('replication_mode',
               default='full-sync',
               help='Replication protocols that define how data is synchronized between primary and secondary hosts'),
    cfg.StrOpt('replication_internal_secret',
               help='Unique replication internal secret shared between replicated hosts and used in web requests'),
    cfg.IntOpt('replication_starting_port',
               default=7001,
               help='Initial starting port to connect replicated volumes.'),
    cfg.IntOpt('replication_resync_rate',
               default=100,
               help='The bandwidth for replication.'),
]
CONF = cfg.CONF
CONF.register_opts(replication_opts)

RESOURCE_META = 'ev3_meta'

class ReplicatedVolumeBackendAPIException(exception.VolumeBackendAPIException):
    message = _("Bad or unexpected response from the replicated volume backend API: %(data)s")

class ReplicatedVolumeBackendRetryableException(exception.VolumeBackendAPIException):
    message = _("Retryable replicated volume backend API Exception encountered")

retry_tuple = (ReplicatedVolumeBackendRetryableException,)

@interface.volumedriver
class ReplicatedVolumeDriver(LVMVolumeDriver):
    """Executes commands relating to Volumes."""

    VERSION = '3.0.0'
    # ThirdPartySystems wiki page
    CI_WIKI_NAME = "Cinder_Jenkins"

    def __init__(self, *args, **kwargs):
        # Parent sets db, host, _execute and base config
        # replication_status: disabled
        # self.SUPPORTS_ACTIVE_ACTIVE = True
        super(ReplicatedVolumeDriver, self).__init__(*args, **kwargs)
        self.configuration.append_config_values(replication_opts)


    def _init_vendor_properties(self):
        properties = {}
        self._set_property(
            properties,
            "ovt_ev3:replication_mode",
            "Replication mode",
            _("Specifies replication mode."),
            "string",
            enum=['async', 'semi-sync', 'full-sync'])
        return properties, 'ovt_ev3'


    def check_for_setup_error(self):
        super().check_for_setup_error()
        resource_meta_dir = f"{CONF.get('state_path')}/{RESOURCE_META}"
        if not os.path.exists(resource_meta_dir):
            try:
                os.makedirs(resource_meta_dir)
            except FileExistsError:
                LOG.info(f"directory {resource_meta_dir} already exist.")
            except OSError as e:
                LOG.error(f"Error creating {resource_meta_dir}: {e}")

        if self.configuration.backend_ip is None:
            LOG.warning("The backend_ip value is not specified. Data replication will not be available.")
        else:
            try:
                root_helper = utils.get_root_helper()
                self._execute('drbdadm', 'dump', root_helper=root_helper, run_as_root=True)
            except processutils.ProcessExecutionError as exc:
                exception_message = (_("Failed to initialize replicated volume driver, "
                                       "error message was: %s")
                                     % six.text_type(exc.stderr))
                raise exception.VolumeBackendAPIException(data=exception_message)

        if self.configuration.replication_internal_secret is None:
            LOG.warning("The replication_internal_secret value is not specified. Failed to initialize replicated volume driver correctly.")

        self.listen()

    def create_volume(self, volume):
        super().create_volume(volume)
        return self.setup_replication(volume)


    def delete_volume(self, volume):
        self.delete_replication(volume)
        super().delete_volume(volume)


    def extend_volume(self, volume, new_size):
        super().extend_volume(volume, new_size)
        self.__set_drbd_resource_primary(resource_id=volume.id, force=True)
        if self.extend_replicated_volume(volume, new_size):
            LOG.info(f"Remote replica of volume {volume.id} has been successfully extended up to {new_size}G")
        else:
            LOG.warning(f"Remote replica of volume {volume.id} didn't extended up to {new_size}G")
        self.__resize_drbd_resource(volume.id, new_size)


    def create_snapshot(self, snapshot):
        super().create_snapshot(snapshot)
        snapshot_info = {
            'name': snapshot['name'],
            'volume_name': snapshot['volume_name'],
        }
        for secondary_backend in self.configuration.replication_device:
            endpoint = self.__get_remote_backend_endpoint(secondary_backend)
            secondary_backend_id = secondary_backend['backend_id']
            try:
                self._do_client_request(api_method='/create_snapshot', endpoint=endpoint, data=snapshot_info)
                LOG.info(f"The snapshot {snapshot['name']} of {snapshot['volume_name']} has been created successfully'")
            except ReplicatedVolumeBackendAPIException as a:
                LOG.error(f"The snapshot {snapshot['name']} of {snapshot['volume_name']} "
                          f"on backend {secondary_backend_id } was not created, "
                          f"an ReplicatedVolumeBackendAPIException occurred: {a.message}")
            except ReplicatedVolumeBackendRetryableException as a:
                LOG.error(f"The snapshot {snapshot['name']}  of {snapshot['volume_name']} "
                          f"on backend {secondary_backend_id } was not created, "
                          f"an ReplicatedVolumeBackendRetryableException occurred: {a.message}")


    def delete_snapshot(self, snapshot):
        super().delete_snapshot(snapshot)
        snapshot_info = {
            'name': snapshot['name'],
        }
        for secondary_backend in self.configuration.replication_device:
            endpoint = self.__get_remote_backend_endpoint(secondary_backend)
            secondary_backend_id = secondary_backend['backend_id']
            try:
                self._do_client_request(api_method='/delete_snapshot', endpoint=endpoint, data=snapshot_info)
                LOG.info(f"The snapshot {snapshot['name']} of {snapshot['volume_name']} has been deleted successfully'")
            except ReplicatedVolumeBackendAPIException as a:
                LOG.error(f"The snapshot {snapshot['name']} of {snapshot['volume_name']} "
                          f"on backend {secondary_backend_id} was not deleted, "
                          f"an ReplicatedVolumeBackendAPIException occurred: {a.message}")
            except ReplicatedVolumeBackendRetryableException as a:
                LOG.error(f"The snapshot {snapshot['name']}  of {snapshot['volume_name']} "
                          f"on backend {secondary_backend_id} was not deleted, "
                          f"an ReplicatedVolumeBackendRetryableException  occurred: {a.message}")


    def _update_volume_stats(self):
        """
        Updates the volume stats
        :return: the volume stats
        """
        super()._update_volume_stats()
        replication_enabled = self.configuration.replication_device is not None
        replication_status = fields.ReplicationStatus.ENABLED
        replication_targets = []
        if replication_enabled:
            for replication_device in self.configuration.replication_device:
                if replication_device['backend_id'] is not None:
                    replication_targets.append(replication_device['backend_id'])
            replication_targets.append('default')

        location_info = ('ReplicatedVolumeDriver:%(hostname)s:%(vg)s'
                         ':%(lvm_type)s:%(lvm_mirrors)s' %
                         {'hostname': self.hostname,
                          'vg': self.configuration.volume_group,
                          'lvm_type': self.configuration.lvm_type,
                          'lvm_mirrors': self.configuration.lvm_mirrors})

        self._stats["replication_status"] = replication_status
        self._stats['replication_enabled'] = True
        self._stats['vendor_name'] = 'OVT LLC'
        self._stats['driver_version'] = '2025.1'

        pools = self._stats['pools']
        for pool in pools:
            pool['location_info'] = location_info
            pool['replication_status'] = replication_status
            pool['replication_enabled'] = replication_enabled
            if replication_enabled:
                pool['replication_mode'] = ['async', 'semi-sync', 'full-sync']
                pool['replication_targets'] = replication_targets


    @staticmethod
    def _is_replicated(volume):
        """
        Returns true if volume is replicated
        :param volume: the volume object
        :return: true if the volume is replicated
        """
        specs = getattr(volume.volume_type, 'extra_specs', {})
        return specs.get('replication_enabled') == '<is> True'


    def failover_host(self, context, volumes, secondary_id=None, groups=None):
        """
        Failover to replication target.
        This function combines calls to failover() and failover_completed() to perform failover when Active/Active is not enabled.
        :param context: the openstack context
        :param volumes: the volume object
        :param secondary_id: the secondary backend id
        :param groups: the cinder volume group
        :return:
        """

        model_updates = []
        if secondary_id is None:
            return secondary_id, model_updates, []

        active_backend_id = secondary_id

        if secondary_id == 'default':
            active_backend_id = self.configuration.backend_id

            host = self.configuration.backend_id + '#' + self.configuration.volume_backend_name

            volume_update = {
                'host': host,
                'provider_id': active_backend_id,
                'replication_status': fields.ReplicationStatus.FAILED_OVER,
                'updated_at': datetime.datetime.now(),
            }

            for f in os.listdir(f"{CONF.get('state_path')}/{RESOURCE_META}/"):
                model_updates.append({
                    'volume_id': f,
                    'updates': volume_update,
                })
                self.db.volume_update(context,f,volume_update)
        else:
            for volume in volumes:
                host =  secondary_id + '#' + self.configuration.volume_backend_name
                model_updates.append({
                    'volume_id': volume['id'],
                    'updates': {
                        'host': host,
                        'provider_id': active_backend_id,
                        'replication_status': fields.ReplicationStatus.ENABLED,
                    }
                })

        return active_backend_id, model_updates, []


    @staticmethod
    def __get_remote_backend_endpoint(secondary_backend):
        """
        Extracts and returns ip and port for secondary backend
        :param secondary_backend:
        :return:
        """
        backend_ip = secondary_backend['ip']
        backend_port = secondary_backend['port']
        return f"http://{backend_ip}:{backend_port}"


    def setup_replication(self, volume):
        """
        Setups the replication for pointed volume
        :param volume: the volume object
        :return: None
        """
        repl_status = fields.ReplicationStatus.DISABLED
        resource = self.__get_resource(volume)

        for secondary_backend in self.configuration.replication_device:
            endpoint = self.__get_remote_backend_endpoint(secondary_backend)
            try:
                self._do_client_request(api_method='/create_volume', endpoint=endpoint, data=resource)
                LOG.info(f"Remote drbd resource for {volume['name']} has been created successfully'")
                if repl_status in fields.ReplicationStatus.DISABLED:
                    repl_status = fields.ReplicationStatus.ENABLED
            except ReplicatedVolumeBackendAPIException as a:
                LOG.error(f"The resource for {volume['name']} on backend {secondary_backend} was not created, "
                          f"an ReplicatedVolumeBackendAPIException occurred: {a.message}")
                repl_status = fields.ReplicationStatus.ERROR
            except ReplicatedVolumeBackendRetryableException as a:
                LOG.error(f"The resource for {volume['name']} on backend {secondary_backend} was not created, "
                          f"an ReplicatedVolumeBackendRetryableException occurred: {a.message}")
                repl_status = fields.ReplicationStatus.ERROR

        self.__save_resource_meta(resource)
        self.__setup_drbd_config(resource)
        self.__skipping_initial_resynchronization(resource)

        model_update = {
            'replication_status': repl_status,
            'replication_driver_data': f"device_minor:{resource['device_minor']}",
            'provider_id': self.configuration.backend_id
        }
        return model_update


    def extend_replicated_volume(self, volume, new_size):
        """
        Extends the replicated volume
        :param volume: the volume object
        :param new_size: the new size of replicated object
        :return: None
        """
        resource = self.__get_resource(volume)
        resource['volume_size'] = new_size
        for secondary_backend in self.configuration.replication_device:
            endpoint = self.__get_remote_backend_endpoint(secondary_backend)

            try:
                self._do_client_request(api_method='/extend_volume', endpoint=endpoint, data=resource)
                LOG.info(f"The size of replicated volume {volume['name']} on backend {secondary_backend['backend_id']} "
                         f"was successfully resized to {self._sizestr(new_size)}")
            except ReplicatedVolumeBackendAPIException as a:
                LOG.error(f"The replicated volume {volume['name']} on backend {secondary_backend['backend_id']} was not resized, "
                          f"an ReplicatedVolumeBackendAPIException occurred: {a.message}")
                return False
            except ReplicatedVolumeBackendRetryableException as a:
                LOG.error(f"The replicated volume {volume['name']} on backend {secondary_backend['backend_id']} was not resized. "
                          f"an ReplicatedVolumeBackendRetryableException occurred: {a.message}")
                return False
        return True


    def delete_replication(self, volume):
        """
        Deletes replication for the pointed volume object
        :param volume: the volume object
        :return: None
        """
        resource = {
            'volume_id': volume['id'],
            'volume_name': volume['name']
        }

        for b in self.configuration.replication_device:
            secondary_backend_id = b['backend_id']
            endpoint = self.__get_remote_backend_endpoint(secondary_backend=b)
            try:
                self._do_client_request(api_method='/delete_volume', endpoint=endpoint, data=resource)
                LOG.info(f"Remote drbd resource for {volume['name']} has been remove successfully'")
            except ReplicatedVolumeBackendAPIException as a:
                LOG.error(f"The resource for {volume['name']} on backend {secondary_backend_id} was not deleted, "
                          f"an ReplicatedVolumeBackendAPIException occurred: {a.message}")
            except ReplicatedVolumeBackendRetryableException as a:
                LOG.error(f"The resource for {volume['name']} on backend {secondary_backend_id} was not deleted, "
                          f"an ReplicatedVolumeBackendRetryableException occurred: {a.message}")
        self.__delete_resource_meta(resource)
        self.__remove_drbd_config(resource)


    def __save_resource_meta(self, resource):
        """
        Updates the configuration resource in json format on the file system
        :param resource: resource object as dict
        :return: None
        """
        resource_path = self.__get_resource_path(resource['volume_id'])
        with open(resource_path, "w") as file:
            json.dump(resource, file, indent=4)


    def __delete_resource_meta(self, resource):
        """
        Deletes the configuration resource stored on the file system
        :param resource:
        :return: None
        """
        resource_path = self.__get_resource_path(resource['volume_id'])
        if os.path.exists(resource_path):
            os.remove(resource_path)


    @staticmethod
    def __get_resource_path(resource_id):
        """
        Returns the path to the configuration resource stored on the file system
        :param resource_id: resource id
        :return: the path to the configuration resource
        """
        return f"{CONF.get('state_path')}/{RESOURCE_META}/{resource_id}"


    def __get_resource(self, volume) -> dict:
        """
        Makes resource description by volume for secondary backends
        :param volume: cinder volume
        :return: resource object as dict
        """
        minor = self.__allocate_drdb_minors()

        backends = list()
        backends.append({
            'id': self.configuration.backend_id,
            'ip': self.configuration.backend_ip,
            'volume': f"/dev/{self.configuration.volume_group}/{volume.name}"
        })

        for b in self.configuration.replication_device:
            backends.append({
                'id': b['backend_id'],
                'ip': b['ip'],
                'volume': f"/dev/{b['volume_group']}/{volume.name}",
            })

        resource = {
            'volume_id': volume.id,
            'volume_name': volume.name,
            'volume_size': volume.size,
            'device_minor': minor,
            'replication_mode': self.configuration.replication_mode,
            'replication_port': self.configuration.replication_starting_port + minor,
            'backends': backends,
        }
        LOG.info(json.dumps(resource, indent=4))

        return resource

    """
        DRDB resource management
    """
    # TODO check refactoring
    @coordination.synchronized('allocate_drdb_minors')
    def __allocate_drdb_minors(self):
        """
        Allocates drdb minor numbers
        :return: number
        """
        all_entries = os.listdir("/dev")
        # Filter for devices containing "drbd" in their name and ending with numbers
        filtered_devices = fnmatch.filter(all_entries, "drbd[0-9]")
        allocated = []
        for d in filtered_devices:
            index = "".join([char for char in d if char.isdigit()])
            allocated.append(int(index))
        allocated.sort()
        minor_number: int = 0
        for m in allocated:
            if m != minor_number:
                return minor_number
            minor_number += 1
        return minor_number


    def __set_drbd_resource_primary(self, resource_id, force=False):
        """
        Sets the local drbd device primary
        :param resource_id: drbd resource id
        :param force:
        :return: None
        """
        try:
            root_helper = utils.get_root_helper()
            if force:
                self._execute('drbdadm', 'primary', resource_id, '--force', root_helper=root_helper, run_as_root=True)
            else:
                self._execute('drbdadm', 'primary', resource_id, root_helper=root_helper, run_as_root=True)
            LOG.info(f"The replication role was successfully set as primary for the resource {resource_id}")
        except processutils.ProcessExecutionError as e:
            exception_message = (
                    _(f"Failed to purge volume replication {resource_id}, error message was: %s")
                    % six.text_type(e.stderr)
            )
            LOG.error(exception_message)
        except Exception as e:
            LOG.error(f"Failed to initialize replicated volume {resource_id}, an unexpected error occurred: {e}")


    @utils.retry(retry_tuple, interval=2, retries=5)
    def __skipping_initial_resynchronization(self, resource):
        """
        Skips initial sync between drbd devices
        :param resource: resource object
        :return: None
        """
        res_id = resource.get('volume_id')
        try:
            root_helper = utils.get_root_helper()
            self._execute('drbdadm', '--clear-bitmap', 'new-current-uuid', res_id, root_helper=root_helper,
                          run_as_root=True)
        except processutils.ProcessExecutionError as e:
            raise ReplicatedVolumeBackendRetryableException(data=str(e))
        except Exception as e:
            LOG.error(f"Failed to skip initial resynchronization for volume id {res_id}, an error occurred: {e}")
            raise ReplicatedVolumeBackendRetryableException(data=str(e))


    def __setup_drbd_config(self, resource):
        """
        Setups drbd device for replication
        :param resource: resource object as dict
        :return: None
        """
        res_id = resource.get('volume_id')
        protocol = ev3_res.REPLICATION_PROTOCOLS[resource.get('replication_mode')]
        minor = resource.get('device_minor')
        port = resource.get('replication_port')

        backends = ''
        for b in resource.get('backends'):
            backends += ev3_res.BACKEND.format(address=b.get('ip'), port=port, disk=b.get('volume'))

        config = ev3_res.RESOURCE_CONF.format(resource_id=res_id, protocol=protocol, backends=backends, minor=minor).lstrip()

        try:
            self.__write_drbd_config(res_id, config)
            root_helper = utils.get_root_helper()
            LOG.info(f"Created replicated resource {res_id}, device minor is {minor}")
            self._execute('drbdadm', 'create-md', res_id, root_helper=root_helper, run_as_root=True)
            self._execute('drbdadm', 'up', res_id, root_helper=root_helper, run_as_root=True)

            LOG.info(f"Replicated resource {res_id} was successfully started.")

        except IOError as e:
            LOG.error(f"An I/O error occurred while writing the file /etc/drbd.d/{res_id}.res: {e}")
        except processutils.ProcessExecutionError as e:
            exception_message = (
                    _(f"Failed to purge volume replication {res_id}, error message was: %s")
                    % six.text_type(e.stderr)
            )
            LOG.error(exception_message)
        except Exception as e:
            LOG.error(f"Failed to initialize replicated volume {res_id}, an unexpected error occurred: {e}")


    @staticmethod
    def __write_drbd_config(res_id, config_content):
        """
        Safely saves config
        :param res_id:
        :param config_content:
        :return:
        """
        config_path = f"/etc/drbd.d/{res_id}.res"
        tmp_path = config_path + ".tmp"

        # Writing to a temporary file and atomic transfer
        try:
            with open(tmp_path, "w") as f:
                f.write(config_content)
            os.rename(tmp_path, config_path)
        except Exception as e:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise e


    def __remove_drbd_config(self, resource):
        """
        Stops drbd replication and removes drbd configuration
        :param resource: resource object as a dict
        :return: returns true on success
        """
        root_helper = utils.get_root_helper()
        resource_id = resource['volume_id']
        try:
            resource_path = f"/etc/drbd.d/{resource_id}.res"

            if os.path.exists(resource_path):
                self._execute(
                    'drbdadm', 'down', resource_id,
                    root_helper=root_helper, run_as_root=True
                )
                os.remove(resource_path)
                if os.path.exists(f"/dev/drbd/by-res/{resource_id}"):
                    os.unlink(f"/dev/drbd/by-res/{resource_id}/0")
                    os.rmdir(f"/dev/drbd/by-res/{resource_id}")
            return True
        except processutils.ProcessExecutionError as exc:
            exception_message = (
                    _(f"Failed to purge volume replication {resource_id}, error message was: %s")
                    % six.text_type(exc.stderr)
            )
            LOG.error(exception_message)
        return False


    def __resize_drbd_resource(self, resource_id, new_size):
        """
        Invokes resizing of drbd resource
        :param resource_id: drbd resource uuid
        :param new_size: new size
        :return:
        """
        try:
            root_helper = utils.get_root_helper()
            self._execute('drbdadm', '--', '--assume-clean', 'resize', resource_id, root_helper=root_helper,
                          run_as_root=True)
        except processutils.ProcessExecutionError as e:
            exception_message = (
                    _(f"Failed to resize DRBD resource {resource_id}, error message was: %s")
                    % six.text_type(e.stderr)
            )
            LOG.error(exception_message)

    """
        ISCSi block
    """
    def local_path(self, volume, vg=None):
        with open(f"{CONF.get('state_path')}/{RESOURCE_META}/{volume.id}", "r") as file:
            resource = json.load(file)
            return f"/dev/drbd{resource.get('device_minor')}"


    def ensure_export(self, context, volume):
        """
        Ensures iscsi export
        :param context: openstack context
        :param volume: cinder volume
        :return: dict of model update
        """
        LOG.info(str(volume))
        self.__set_drbd_resource_primary(volume['id'])

        volume_path = self.local_path(volume)
        self.vg.activate_lv(volume['name'])

        model_update = \
            self.target_driver.ensure_export(context, volume, volume_path)
        return model_update


    def create_export(self, context, volume, connector, vg=None):
        """
        Creates an iscsi export
        :param context: openstack context
        :param volume: cinder volume
        :param connector:
        :param vg: lvm volume group
        :return: property set of provider location and authorization
        """
        self.__set_drbd_resource_primary(volume['id'])

        if vg is None:
            vg = self.configuration.volume_group

        volume_path = self.local_path(volume)

        self.vg.activate_lv(volume['name'])

        export_info = self.target_driver.create_export(
            context,
            volume,
            volume_path)
        return {'provider_location': export_info['location'],
                'provider_auth': export_info['auth'], }


    def remove_export(self, context, volume):
        self.target_driver.remove_export(context, volume)


    def terminate_connection(self, volume, connector, **kwargs):
        def volume_provider_ips():
            backend_provider_ips = list()
            backend_provider_ips.append(self.configuration.target_ip_address)
            portal_addresses = volume.provider_location.split(' ')[0].split(',')[0].split(';')
            for portal_address in portal_addresses:
                ip, _ = portal_address.split(":")
                if ip in backend_provider_ips:
                    return True
            return False

        if volume.provider_location is not None:
            if not volume_provider_ips():
                volume['provider_location'] = None
                return True

        attachments = volume.volume_attachment
        if volume.multiattach:
            if sum(1 for a in attachments if a.connector and
                                             a.connector['initiator'] == connector['initiator']) > 1:
                return True

        self.target_driver.terminate_connection(volume, connector, **kwargs)
        return len(attachments) > 1

    """ 
         Restful API block
         This is a part that listens for remote web requests from other backends. 
    """
    @staticmethod
    def __get_header(content_length: int, resource_id: str = None):
        """
        Returns header for http request
        :param content_length:  content length as integer value
        :param resource_id: the resource id
        :return: the header for http request
        """
        if resource_id is None:
            return {'Content-Type': 'application/json', 'Content-Length': str(content_length)}
        return {'Content-Type': 'application/json', 'Content-Length': str(content_length),
                'X-OVT-Resource-ID': resource_id}


    @utils.retry(retry_tuple, interval=1, retries=3)
    def _do_client_request(self, api_method, endpoint, data=None):
        """
        Makes the http request to ev3 storage backend
        :param api_method: the http request method
        :param endpoint: the endpoint
        :param data: the data posted to backend in json format
        :return: the response from storage backend in json format, raise ReplicatedVolumeBackendRetryableException if
        response state code != 200
        """
        if data is None:
            data = {}

        now_utc = datetime.datetime.now().isoformat() + 'Z'
        secret_key = f"EV3{self.configuration.replication_internal_secret}".encode('utf-8')
        hmac_digest = hmac.new(secret_key, now_utc.encode('utf-8'), hashlib.sha256)
        headers = {ev3_res.HTTP_HEADER_X_EV3_TOKEN: hmac_digest.hexdigest(), ev3_res.HTTP_HEADER_X_EV3_DATE: now_utc }

        try:
            with requests.post(url=f"{endpoint}{api_method}", headers=headers, json=data) as resp:
                if resp.status_code == 200:
                    return resp.json()
                else:
                    return resp.text
        except requests.exceptions.ConnectionError as a:
            raise ReplicatedVolumeBackendRetryableException(data=str(a))

    """
        OVT ev3 Backend Server / OVT ev3 Restful API 
    """
    def __call__(self, environ, start_response):
        """
        A replicated backend WSGI application"
        """
        req = Request(environ)
        resp = Response()

        # begin block: token check
        ev3_date = req.headers.get(ev3_res.HTTP_HEADER_X_EV3_DATE)
        token = req.headers.get(ev3_res.HTTP_HEADER_X_EV3_TOKEN)

        if ev3_date is None or token is None:
            resp.status_code = 403
            return resp(environ, start_response)

        secret_key = f"EV3{self.configuration.replication_internal_secret}".encode('utf-8')
        hmac_digest = hmac.new(secret_key, ev3_date.encode('utf-8'), hashlib.sha256)
        if token != hmac_digest.hexdigest():
            resp.status_code = 403
            resp(environ, start_response)
        # end block: token check

        try:
            if req.method == 'GET' and req.path == '/heartbeat':
                resp.status_code = 200
                resp.text = 'alive'
            elif req.method == 'POST' and req.path == '/create_volume':
                resource = req.json
                self.__save_resource_meta(resource)
                super()._create_volume(resource['volume_name'],
                                       self._sizestr(resource['volume_size']),
                                       self.configuration.lvm_type,
                                       0)

                self.__setup_drbd_config(resource)
                resp.status_code = 200
                resp.json = {}
                LOG.info(f"The volume replica {resource['volume_id']} was successfully created")
            elif req.method == 'POST' and req.path == '/create_snapshot':
                snapshot = req.json
                self.vg.create_lv_snapshot(self._escape_snapshot(snapshot['name']),
                                           snapshot['volume_name'],
                                           self.configuration.lvm_type)
                resp.status_code = 200
                resp.json = {}
                LOG.info(f"The volume snapshot replica {snapshot['name']} was successfully created")
            elif req.method == 'POST' and req.path == '/delete_volume':
                resource = req.json
                self.__remove_drbd_config(resource)
                self.__delete_resource_meta(resource)
                volume = {
                    'id': resource['volume_id'],
                    'name': resource['volume_name']
                }
                super()._delete_volume(volume)
                resp.status_code = 200
                resp.json = {}
                LOG.info(f"The volume replica {resource['volume_id']} was successfully deleted")
            elif req.method == 'POST' and req.path == '/delete_snapshot':
                snapshot = req.json
                message = f"The volume snapshot replica {snapshot['name']} was successfully deleted"
                if self._volume_not_present(self._escape_snapshot(snapshot['name'])):
                    # If the snapshot isn't present, then don't attempt to delete
                    message = f"Snapshot: {snapshot['name']} not found, skipping delete operations"
                else:
                    super()._delete_volume(snapshot, True)

                resp.status_code = 200
                resp.json = {
                    'message': message
                }
                LOG.info(message)
            elif req.method == 'POST' and req.path == '/extend_volume':
                resource = req.json
                new_size = self._sizestr(resource['volume_size'])
                self.vg.extend_volume(resource['volume_name'], self._sizestr(new_size))
                resp.status_code = 200
                resp.json = {}
                message = f"The volume {resource['volume_id']} has been successfully extended up to {resource['volume_size']}G"
                LOG.info(message)
            else:
                resp.status_code = 404
                resp.text = 'Not Found'
        except IOError as e:
            resp.status_code = 500
            resp.text = f"An I/O error occurred while writing the file /etc/drbd.d/resource_id.res: {e}"
        except Exception as e:
            resp.status_code = 500
            resp.text = f"An unexpected error occurred: {e}"
        return resp(environ, start_response)


    def listen(self):
        def serve_forever(log: logging):
            port = self.configuration.backend_port
            address = self.configuration.backend_ip
            with make_server(address, port, self.__call__) as httpd:
                # Serve requests forever
                log.info(f'Storage agent is listing on port {port}')
                httpd.serve_forever()
        thread = Thread(target=serve_forever, args=(LOG,))
        thread.daemon = True
        thread.start()
