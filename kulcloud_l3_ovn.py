# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 OpenStack Foundation.
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

import sys
import json
import http.client
import socket

from oslo_log import log
from oslo_config import cfg
from neutron_lib import exceptions

from networking_ovn.l3.l3_ovn import OVNL3RouterPlugin

LOG = log.getLogger(__name__)

SUCCESS_CODES = list(range(200, 207))
FAILURE_CODES = [0, 301, 302, 303, 400, 401, 403, 404, 500, 501, 502, 503, 504, 505]

ROUTER_NAME_MAX_LENGTH = 11
ROUTER_PATH = "/routers"
ROUTER_INTERFACE_PATH = "/router/interfaces"
NETWORK_DHCP_PATH = "/networks/dhcp"
FLOATING_PATH = "/flowtable/%s/flow/float"

KUL_OPTS = [
    cfg.StrOpt('server',
               default="localhost",
               help=_("")),
    cfg.IntOpt('port',
               default=8181,
               help=_("")),
    cfg.StrOpt('base_uri',
               default='/1.1/openstack',
               help=_("")),
    cfg.IntOpt('timeout',
               default=5,
               help=_("")),
    cfg.StrOpt('intf_prefix',
               default='prvlan',
               help=_("")),
]

cfg.CONF.register_opts(KUL_OPTS, "nbapi")


class NBAPIException(exceptions.NeutronException):
    message = _("Fail NBAPI requests : %(msg)s")


class NBAPIBadConnect(exceptions.NeutronException):
    message = _("Not connected to NBAPI server")


class KulcloudOVNL3RouterPlugin(OVNL3RouterPlugin):

    """Implementation of the Neutron L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    All DB related work is implemented in classes
    l3_db.L3_NAT_db_mixin and extraroute_db.ExtraRoute_db_mixin.
    """
    def __init__(self):
        super(KulcloudOVNL3RouterPlugin, self).__init__()
        self.nbapi_server = cfg.CONF.nbapi.server
        self.nbapi_port = cfg.CONF.nbapi.port
        self.base_uri = cfg.CONF.nbapi.base_uri
        self.time_out = cfg.CONF.nbapi.timeout
        self.intf_prefix = cfg.CONF.nbapi.intf_prefix
        self.success_codes = SUCCESS_CODES
        self.failure_codes = FAILURE_CODES


    def rest_call(self, action, url, data, headers,
                  https=False, base_uri=None):
        if base_uri == None:
            base_uri = self.base_uri
        uri = base_uri + url
        body = json.dumps(data)
        if not headers:
            headers = {}
        headers['Content-type'] = 'application/json'
        headers['Accept'] = 'application/json'

        if https is False:
            conn = http.client.HTTPConnection(
                self.nbapi_server, port=self.nbapi_port,
                timeout=self.time_out)
        else:
            conn = http.client.HTTPSConnection(
                self.nbapi_server, port=self.nbapi_port,
                timeout=self.time_out)

        if conn is None:
            #return 0, None, None, None
            raise NBAPIException(msg="Fail to create socket")

        try:
            conn.request(action, uri, body, headers)
            response = conn.getresponse()
            respstr = response.read()
            respdata = respstr
            if response.status in self.success_codes:
                try:
                    respdata = json.loads(respstr)
                except ValueError:
                    pass
            ret = (response.status, response.reason, respstr, respdata)
        except (socket.timeout, socket.error) as e:
            LOG.error(_('RESTCALL: %(action)s failure, %(e)r'),
                      {'action' : action, 'e' : e})
            #ret = 0, None, None, None
            raise NBAPIException(msg="Not connected to NBAPI server")
        finally:
            conn.close()

        return ret


    def create_router(self, context, router):
        router_dict = super(KulcloudOVNL3RouterPlugin, self).create_router(
            context, router)
        try:
            router_name = router_dict.get("name")
            router_id = router_dict.get("id")
            remake_router_name = self.__remake_router_name(
                router_name, router_id)
            result = self.__send_create_router(remake_router_name)
            return router_dict

        except Exception as e:
            LOG.exception(" ")
            super(KulcloudOVNL3RouterPlugin, self).delete_router(
                context, router_dict['id'])
            raise e


    def update_router(self, context, id, router):
        r_dict = super(KulcloudOVNL3RouterPlugin, self).update_router(
            context, id, router)
        return r_dict


    def delete_router(self, context, router_id):
        router = super(KulcloudOVNL3RouterPlugin, self).get_router(
            context, router_id, 'name')
        super(KulcloudOVNL3RouterPlugin, self).delete_router(context, router_id)

        try:
            router_name = router.get("name")
            remake_router_name = self.__remake_router_name(
                router_name, router_id)
            self.__send_delete_router(remake_router_name)
        except Exception as e:
            LOG.exception(" ")
            raise e


    def add_router_interface(self, context, router_id, interface_info):
        info = super(KulcloudOVNL3RouterPlugin, self).add_router_interface(
            context, router_id, interface_info)
        port = self._core_plugin.get_port(context, info['port_id'])
        network = self._core_plugin.get_network(context, info['network_id'])

        router_name = self.get_router(context, router_id)['name']
        remake_router_name = self.__remake_router_name(
            router_name, router_id)

        if 'provider:segmentation_id' not in network:
            self._core_plugin._extend_network_dict_provider(context, network)

        vlan_id = network['provider:segmentation_id']
        intf_name = "{}{}".format(self.intf_prefix, vlan_id)
        ip = port['fixed_ips'][0]['ip_address']
        cidr = self._core_plugin.get_subnet(context, info['subnet_id'])['cidr']

        try:
            self.__send_add_router_interface(
                intf_name, remake_router_name, ip, cidr, vlan_id)
        except NBAPIException as e:
            LOG.exception("")
            rem_info = {"port_id" : info['port_id']}
            self.remove_router_interface(context, router_id, rem_info)
            raise e

        LOG.info(info)
        return info


    def remove_router_interface(self, context, router_id, interface_info):
        router_name = self.get_router(context, router_id)['name']
        remake_router_name = self.__remake_router_name(router_name, router_id)
        network_id = self._core_plugin.get_port(
            context, interface_info['port_id'])['network_id']
        network = self._core_plugin.get_network(context, network_id)

        if 'provider:segmentation_id' not in network:
            self._core_plugin._extend_network_dict_provider(context, network)

        vlan_id = network['provider:segmentation_id']
        intf_name = "{}{}".format(self.intf_prefix, vlan_id)
        info = super(KulcloudOVNL3RouterPlugin, self).remove_router_interface(
            context, router_id, interface_info)
        self.__delete_router_interface(remake_router_name, intf_name)

        return info


    def make_dhcp_process_info(self, intf_name, ip, cidr, network,
                               tenant_id=None, router_name=None):
        hosts_info = self.__make_hosts_info(network)
        addn_hosts_info = self.__make_addn_hosts_info(network)
        opts_info = self.__make_dhcp_opts_info(network)
        self.__send_run_dhcp_process(
            intf_name, ip, cidr, hosts_info, addn_hosts_info,
            opts_info, tenant_id=tenant_id, router_name=router_name)


    def create_floatingip(self, context, floatingip):
        """Create floating IP.

        :param context: Neutron request context
        :param floatingip: data for the floating IP being created
        :returns: A floating IP object on success

        As the l3 router plugin asynchronously creates floating IPs
        leveraging the l3 agent, the initial status for the floating
        IP object will be DOWN.

        result form is like below :
        {'floating_network_id': u'21630e38-c683-4219-89c9-9a3a7a9f8ab4',
         'router_id': None,
         'fixed_ip_address': None,
         'floating_ip_address': u'172.24.4.5',
         'tenant_id': u'b7b5b6be923d464481d5a08beaf31b96',
         'status': 'DOWN',
         'port_id': None,
         'id': '44242860-8fa9-4728-af87-e8cc86a2422c'}
        """
        result = super(KulcloudOVNL3RouterPlugin, self).create_floatingip(
            context, floatingip)

        return result


    def update_floatingip(self, context, id, floatingip):
        ip = None
        floating_ip = None

        """
        if floatingip['floatingip']['port_id'] == None:
            old_floating = self.get_floatingip(context, id)
            ip = old_floating['fixed_ip_address']
            floating_ip = old_floating['floating_ip_address']
            #self.__send_disallocate_floatingip(ip, floating_ip)
        """

        result = super(KulcloudOVNL3RouterPlugin, self).update_floatingip(
            context, id, floatingip)

        """
        if floatingip['floatingip']['port_id'] != None:
            ip = result['fixed_ip_address']
            floating_ip = result['floating_ip_address']
            #self.__send_allocate_floatingip(ip, floating_ip)
        """

        return result


    def __send_disallocate_floatingip(self, ip, floating_ip):
        url = FLOATING_PATH % "prism"
        body = dict(fixed_ip_address=ip,
                    floating_ip_address=floating_ip)
        res = self.rest_call("DELETE", url, body, None, base_uri="/1.0")


    def __send_allocate_floatingip(self, ip, floating_ip):
        url = FLOATING_PATH % "prism"
        body = dict(fixed_ip_address=ip,
                    floating_ip_address=floating_ip)
        res = self.rest_call("POST", url, body, None, base_uri="/1.0")


    def __send_create_router(self, name, **kwargs):
        url = ROUTER_PATH
        body = dict(name=name)

        res = self.rest_call("POST", url, body, None)

        if res[0] not in SUCCESS_CODES:
            raise NBAPIException(msg=res[2])

        return res


    def __send_delete_router(self, name):
        url = "/".join((ROUTER_PATH, name))

        res = self.rest_call("DELETE", url, None, None)
        if res[0] not in SUCCESS_CODES:
            msg = res[2]
            if not msg.startswith(b'{"error": "Not found tenant'):
                raise NBAPIException(msg=res[2])


    def __send_add_router_interface(self, intf_name,
                                    router_name, ip, cidr, segment_id=None):
        url = ROUTER_INTERFACE_PATH
        cidr_int = cidr.split('/')[-1]
        body = dict(
            tenant_name=router_name,
            intf_name=intf_name,
            vlan_id=segment_id,
            ip_address="{}/{}".format(ip, cidr_int)
        )
        LOG.info("Send add router intf API to NBAPI server {}:{}".format(
            self.nbapi_server, self.nbapi_port))
        LOG.info("Body: {}".format(body))

        res = self.rest_call("POST", url, body, None)
        if res[0] not in SUCCESS_CODES:
            raise NBAPIException(msg=res[2])
        return res


    def __delete_router_interface(self, router_name, intf_name):
        url = "{}/{}?tenant_name={}".format(
            ROUTER_INTERFACE_PATH, intf_name, router_name)
        res = self.rest_call("DELETE", url, None, None)
        if res[0] == 0:
            raise NBAPIException(msg=res[2])

        return res


    def __send_run_dhcp_process(self, intf_name, ip, cidr,
                                hosts=None, addn_hosts=None, opts=None,
                                tenant_id=None, router_name=None):
        url = NETWORK_DHCP_PATH
        body = dict(intf_name=intf_name,
                    ip_address=ip,
                    network_cidr=cidr,
                    hosts=hosts,
                    addn_hosts=addn_hosts,
                    opts=opts,
                    tenant_id=tenant_id,
                    router_name=router_name)
        res = self.rest_call("POST", url, body, None)
        if res[0] == 0:
            raise NBAPIException(msg=res[2])

        return res


    def __send_kill_dhcp_process(self, router_name, intf_name):
        url = "%s/%s/%s" % (NETWORK_DHCP_PATH, router_name, intf_name)
        res = self.rest_call("DELETE", url, None, None)
        if res[0] == 0:
            raise RuntimeError(res)

        return res


    def __iter_hosts(self, network):
        dhcp_domain = "openstacklocal"

        for port in network.ports:
            for alloc in port.fixed_ips:
                hostname = 'host-%s' % alloc.ip_address.replace(
                    '.', '-').replace(':', '-')
                name = '%s.%s' % (hostname, dhcp_domain)
                yield (port, alloc, hostname, name)


    def __make_hosts_info(self, network):
        # static value
        result = []

        for (port, alloc, hostname, name) in self.__iter_hosts(network):
            if getattr(port, 'extra_dhcp_opts', False):
                # Don't check version
                result.append(dict(mac_address=port.mac_address,
                                   name=name,
                                   ip_address=alloc.ip_address,
                                   set_tag='set:',
                                   port_id=port.id))
            else:
                result.append(dict(mac_address=port.mac_address,
                                   name=name,
                                   ip_address=alloc.ip_address))

        return result


    def __make_addn_hosts_info(self, network):
        result = []

        for (port, alloc, hostname, name) in self.__iter_hosts(network):
            result.append(dict(ip_address=alloc.ip_address,
                               name=name,
                               hostname=hostname))

        return result


    def __format_option(self, tag, option, *args):
        # Ignore dnsmasq's version
        set_tag = 'tag:'

        option = str(option)

        if isinstance(tag, int):
            tag = 'tag%d' % tag

        if not option.isdigit():
            option = 'option:%s' % option

        return ','.join((set_tag + tag, '%s' % option) + args)


    def __make_dhcp_opts_info(self, network):
        # Ignore enable_isolated_metadata opt in dhcp_agent.ini
        options = []

        isolated_subnets = {}
        subnets = dict((subnet.id, subnet) for subnet in network.subnets)
        for port in network.ports:
            if port.device_owner != constants.DEVICE_OWNER_ROUTER_INTF:
                continue
            for alloc in port.fixed_ips:
                if subnets[alloc.subnet_id].gateway_ip == alloc.ip_address:
                    isolated_subnets[alloc.subnet_id] = False

        dhcp_ips = {}
        subnet_idx_map = {}
        for i, subnet in enumerate(network.subnets):
            if not subnet.enable_dhcp:
                continue
            if subnet.dns_nameservers:
                options.append(
                    self.__format_option(i, 'dns-server',
                                         ','.join(subnet.dns_nameservers)))
            else:
                subnet_idx_map[subnet.id] = i

            gateway = subnet.gateway_ip
            host_routes = []
            if hasattr(subnet, 'host_routes'):
                for hr in subnet.host_routes:
                    if hr.destination == "0.0.0.0/0":
                        if not gateway:
                            gateway = hr.nexthop
                    else:
                        host_routes.append("%s,%s" % (hr.destination, hr.nexthop))

            # Ignore enable_isolated_metadata opt
            """
            if (isolated_subnets[subnet.id] and
                    self.conf.enable_isolated_metadata and
                    subnet.ip_version == 4):
                subnet_dhcp_ip = subnet_to_interface_ip[subnet.id]
                host_routes.append(
                    '%s/32,%s' % (METADATA_DEFAULT_IP, subnet_dhcp_ip)
                )
            """
            WIN2k3_STATIC_DNS = 249

            if host_routes:
                if gateway and subnet.ip_version == 4:
                    host_routes.append("%s,%s" % ("0.0.0.0/0", gateway))
                options.append(
                    self.__format_option(i, "classless-static-route",
                                         ','.join(host_routes)))
                options.append(
                    self.__format_option(i, WIN2k3_STATIC_DNS,
                                         ','.join(host_routes)))

            if subnet.ip_version == 4:
                if gateway:
                    options.append(self.__format_option(i, 'router', gateway))
                else:
                    options.append(self.__format_option(i, 'router'))

        for port in network.ports:
            if getattr(port, 'extra_dhcp_opts', False):
                options.extend(
                    self.__format_option(port.id, opt.opt_name, opt.opt_value)
                    for opt in port.extra_dhcp_opts)

            if port.device_owner == constants.DEVICE_OWNER_DHCP:
                for ip in port.fixed_ips:
                    i = subnet_idx_map.get(ip.subnet_id)
                    if i is None:
                        continue
                    dhcp_ips[i] = list()
                    dhcp_ips[i].append(ip.ip_address)

        for i, ips in list(dhcp_ips.items()):
            if len(ips) > 1:
                options.append(self.__format_option(i,
                                                    'dns-server',
                                                    ','.join(ips)))

        return options

    def _update_dhcp_info(self, intf_name, network, hosts_ip=None):

        if network:
            hosts_info = self.__make_hosts_info(network)
            addn_hosts_info = self.__make_addn_hosts_info(network)
            opts_info = self.__make_dhcp_opts_info(network)
            cidr = network.subnets[0].cidr
        else:
            hosts_info = None
            addn_hosts_info = None
            opts_info = None
            cidr = None

        self.__send_update_dhcp_info(intf_name,
                                     cidr,
                                     hosts_info,
                                     addn_hosts_info,
                                     opts_info,
                                     hosts_ip=hosts_ip)


    def __send_update_dhcp_info(self, intf_name, cidr,
                                hosts, addn_hosts, opts,
                                hosts_ip=None):
        if intf_name == None:
            inft_name = "None"

        url = "/networks/dhcp/%s" % intf_name
        body = dict(hosts=hosts,
                    network_cidr=cidr,
                    addn_hosts=addn_hosts,
                    opts=opts)
        if hosts_ip:
            body['host_ips'] = hosts_ip

        res = self.rest_call("PUT", url, body, None)
        if res[0] == 0:
            raise RuntimeError(res)

        return res


    def __remake_router_name(self, router_name, router_id):
        remake_router_name = router_id[:ROUTER_NAME_MAX_LENGTH].replace('-', '')
        return remake_router_name
