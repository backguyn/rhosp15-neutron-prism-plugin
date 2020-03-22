
FROM registry.redhat.io/rhosp15-rhel8/openstack-neutron-server:latest
MAINTAINER kulcloud <backguyn.jung@kulcloud.net>

###Required Labels
LABEL name="rhosp15/openstack-neutron-server-prism" \
      maintainer="backguyn.jung@kulcloud.net" \
      vendor="kulcloud" \
      version="1.0.6" \
      release="1.0.6" \
      summary="Red Hat OpenStack Platform 15.0 neutron-server PRISM plugin" \
      description="Red Hat OpenStack Platform 15.0 neutron-server PRISM plugin"

USER "root"

COPY kulcloud_plugin.py /usr/lib/python3.6/site-packages/neutron/plugins/ml2/
COPY kulcloud_l3_router_plugin.py /usr/lib/python3.6/site-packages/neutron/services/l3_router/
COPY ml2_nbapi_conf.txt /tmp
RUN cat /tmp/ml2_nbapi_conf.txt >> /etc/neutron/plugins/ml2/ml2_conf.ini
COPY entry_points.txt /usr/lib/python3.6/site-packages/neutron-14.0.5.dev40-py3.6.egg-info/entry_points.txt

RUN mkdir /licenses
COPY licensing.txt /licenses

USER "neutron"

