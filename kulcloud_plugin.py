# Copyright (c) 2013 OpenStack Foundation
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
#
# For Openstack neutron ML2 plugin (version: liberty)

import sys

from oslo_config import cfg
from oslo_log import log
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron.common import config
from neutron.plugins.ml2.plugin import Ml2Plugin
from neutron.plugins.common import constants as service_constants

from novaclient.v2 import client as nova_client
from novaclient import exceptions

LOG = log.getLogger(__name__)

class KulcloudMl2Plugin(Ml2Plugin):

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

    def create_port(self, context, port):
        res = super(KulcloudMl2Plugin, self).create_port(context, port)
        
        try:
            if port['port']['device_owner'].startswith("compute"):
                _network = self._get_network(context, res['network_id'])
                network = self.get_network(context, res['network_id'])
                vlan_id = network['provider:segmentation_id']
                intf_name = "prvlan%d" % vlan_id
                ip_list = [r['ip_address'] for r in res['fixed_ips']]
                hosts_ip = {"update" : "create", "ip_list" : ip_list}
                self.__update_dhcp_info(intf_name, _network, hosts_ip=hosts_ip)

            return res
        except RuntimeError as e:
            LOG.exception("")
            self.delete_port(context, result['id'])
            return res



    def delete_port(self, context, id, l3_port_check=True):
        port = self.get_port(context, id)
        ip_list = [ip['ip_address'] for ip in port['fixed_ips']]
        hosts_ip = {"update" : "delete", "ip_list" : ip_list}

        res = super(KulcloudMl2Plugin, self).delete_port(
                            context, id, l3_port_check=l3_port_check)

        if port["device_owner"].startswith("compute"):
            self.__update_dhcp_info(None, None, hosts_ip=hosts_ip)


    def __update_dhcp_info(self, intf_name, network, hosts_ip=None):
        l3plug = directory.get_plugin(plugin_constants.L3)
        l3plug._update_dhcp_info(intf_name, network, hosts_ip=hosts_ip)


    def get_instance_info(self, context):
        params = {
            'bypass_url' : cfg.CONF.nova_url,
            'auth_token' : context.auth_token
        }

        params['auth_url'] = cfg.CONF.keystone_authtoken.auth_uri

        client = nova_client.Client(**params)
