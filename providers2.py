import boto
import requests
import ovh
import hashlib
from ArubaCloud.PyArubaAPI import CloudInterface
from ArubaCloud.objects import SmartVmCreator, ProVmCreator


class Provider(object):

    ROOT_URL_OVH = "https://eu.api.ovh.com/1.0/"
    ROOT_URL_CW = "https://compute.fr1.cloudwatt.com/v2/"
    ROOT_URL_CW_NET = "https://network.fr1.cloudwatt.com/"
    ROOT_URL_DO = "https://api.digitalocean.com/v2"
    ROOT_URL_GO = "https://www.googleapis.com/compute/v1/projects"
    ROOT_URL_NU = "https://api2.numergy.com"
    ROOT_URL_RS = "https://lon.servers.api.rackspacecloud.com/v2"

    @classmethod
    class Server(object):
        @staticmethod
        def generate_rsa(bits=2048):
                """
                Generate an RSA keypair with an exponent of 65537 in PEM format
                param: bits The key length in bits
                Return private key and public key
                :param bits:
                """
                from Crypto.PublicKey import RSA
                new_key = RSA.generate(bits, e=65537)
                public_key = new_key.publickey().exportKey("PEM")
                private_key = new_key.exportKey("PEM")
                return private_key, public_key

        @classmethod
        def numergy(cls, accesskey, secretkey, tenantid, imgname=None, appname=None, flavor=None, servername=None,
                    serverid=None, rebuild=None, remove=None, reboot=None, insert=None):

            global imageid, flavorid, _version, imgkey, apps, ipid
            request = requests.get(Provider.ROOT_URL_NU)
            data = request.json()
            for i in (data['versions']['version']):
                if "CURRENT" in i['status']:
                    _version = i['id']

            body = '{"auth": {"apiAccessKeyCredentials": {"accessKey": "%s","secretKey": "%s" },"tenantId": "%s"}}' % (
                accesskey, secretkey, tenantid)
            request = requests.post(Provider.ROOT_URL_NU + "/%s/tokens" % _version, data=body)
            data = request.json()
            _token = (data['access']['token']['id'])

            os = ["Windows Server 2008 R2 ENT 64", "Windows Server 2008 R2 STD 64", "Windows Server 2012 R2 STD 64",
                  'Windows Server 2008 R2 STD EN', 'CentOS 6', 'Redhat 6', 'Redhat 5',
                  'Ubuntu 14.04', 'Ubuntu 12.04', 'Debian 7', 'Debian 8']
            for nos in os:
                if imgname not in nos:
                    raise Exception("Image Error")
                else:
                    if 'Windows' in imgname and appname is None:
                        imgkey = ''.join((list(imgname.split()[0])[:3])) + imgname.split()[2] + " " + \
                                     imgname.split()[3] + " " + imgname.split()[4] + " " + imgname.split()[5]
                    elif 'Windows' in imgname and "IIS" in appname:
                        imgkey = ''.join((list(imgname.split()[0])[:3])) + imgname.split()[2] + " " + \
                             imgname.split()[3] + " " + appname + " " + imgname.split()[4] + " " + \
                                 imgname.split()[5]
                    elif 'windows' in imgname and "SQL" in appname:
                        if "2008" in imgname.split()[2]:
                            apps = "MSSQL STD"
                        else:
                            apps = "SQL 2014 STD"
                            imgkey = ''.join((list(imgname.split()[0])[:3])) + \
                                     imgname.split()[2] + " " +  \
                                     imgname.split()[3] + " " + apps + " " + \
                                     imgname.split()[5]
                    elif appname is None:
                        imgkey = "".join(list(imgname.split()[0])[:3])+"".join(list(imgname.split()[-1])[:2])+"_64"
                    else:
                        if "lamp" and "mysql" in appname and "centOS" or "Redhat" or "Ubuntu 12.04" in nos:
                            apps = {"lamp", 'mysql'}
                            for iapps in apps:
                                imgkey = "".join(list(imgname.split()[0])[:3])+"".join(list(imgname.split()[-1])[:2]) \
                                         + iapps + "64"

            request = requests.get(Provider.ROOT_URL_NU+"/%s/%s/images" % (_version, tenantid),
                                   headers={"X-Auth-Token": "%s" % _token})
            data = request.json()

            for i in (data['images']):
                if imgkey in i['name']:
                    imageid = i['id']

            request = requests.get(Provider.ROOT_URL_NU + "/%s/%s/flavors" % (_version, tenantid),
                                   headers={"X-Auth-Token": "%s" % _token})
            data = request.json()
            for i in (data["flavors"]):
                if flavor in i["name"]:
                    flavorid = i['id']

            if insert:
                _body = '{"server": {"flavorRef": %s,"imageRef": %s,"name": %s,"password_delivery": API}}' % (
                    flavorid, imageid, servername)
                request = requests.post(Provider.ROOT_URL_NU+"/%s/%s/servers" % (_version, tenantid),
                                        headers={"X-Auth-Token": "%s" % _token}, data=_body)
                data = request.json()
                for i in data['servers']:
                    if servername in i['name']:
                        serverid = i['id']
                request = requests.get(Provider.ROOT_URL_NU+"/%s/%s/os-floating-ips" % (_version, tenantid),
                                       headers={"X-Auth-Token": "%s" % _token})
                data = request.json()
                for i in data['floating_ips']:
                    if 'false' in i['blocked']:
                        ipid = i['id']
                _body = '{"add_floating_ip": {"floating_ip_id": "%s"}}' % ipid
                requests.post(Provider.ROOT_URL_NU+"/%s/%s/servers/%s/action" % (_version, tenantid, serverid),
                              headers={"X-Auth-Token": "%s" % _token}, data=_body)

            elif reboot:
                _body = '{"reboot": {"type": "SOFT"}}'
                requests.post(
                    Provider.ROOT_URL_NU + "/%s/%s/servers/%s/reboot" % (_version, tenantid, serverid),
                    data=_body, headers={"X-Auth-Token": "%s" % _token})
            elif remove:
                requests.delete(Provider.ROOT_URL_NU + "/%s/%s/servers/%s" % (_version, tenantid, serverid),
                                headers={"X-Auth-Token": "%s" % _token})
            elif rebuild:
                _body = '{"server": {"flavorRef": %s,"imageRef": %s,"name": %s,"password_delivery": API}}' % (
                    flavorid, imageid, servername)
                requests.post(Provider.ROOT_URL_NU + "/%s/%s/servers/%s" % (_version, tenantid, serverid),
                              headers={"X-Auth-Token": "%s" % _token}, data=_body)
            else:
                return 'error'

        @classmethod
        def cloudwatt(cls, username, password, tenantid, image=None, flavor=None, serverid=None, servername=None,
                      number=None, servpass=None, rebuild=None, reboot=None, remove=None, insert=None):
            global imageid, IP, flavorid, key
            _body = "<?xml version='1.0' encoding='UTF-8'?>" \
                    "<auth xmlns='http://docs.openstack.org/identity/v2.0' tenantName='%s'>" \
                    "<passwordCredentials username='%s' password='%s'/></auth>" % (tenantid, username, password)
            request = requests.post("https://identity.fr1.cloudwatt.com/v2/tokens", data=_body)
            data = request.json()
            token = data['access']['token']['id']

            request = requests.get("https://compute.fr1.cloudwatt.com/v2/%s/images" % tenantid,
                                   headers={"X-Auth-Token": "%s" % token})
            data = request.json()
            for i in (data['images']):
                if image in i['name']:
                    imageid = i['id']

            request = requests.get("https://compute.fr1.cloudwatt.com/v2/%s/flavors" % tenantid,
                                   headers={"X-Auth-Token": "%s" % token})
            data = request.json()
            for i in (data['flavors']):
                if flavor in i['name']:
                    flavorid = i['id']

            if insert:
                # Get Security Group
                _body = '{"security_group":{"name":"Security","description":"SecGroup"}}'
                request = requests.post(Provider.ROOT_URL_CW_NET + "security-groups",
                                        headers={"X-Auth-Token": "%s" % token}, data=_body)
                data = request.json()
                secgroup = data['security_group']['name']
                # Get Network Id
                _body = '{"network":{"name": "network1", "admin_state_up": true}}'
                request = requests.post(Provider.ROOT_URL_CW_NET + "security-groups",
                                        headers={"X-Auth-Token": "%s" % token}, data=_body)
                data = request.json()
                netid = data['network']['id']
                _body = '{"subnet":{"network_id":"%s","ip_version":4,"cidr":"192.168.0.0/24"}}' % netid
                requests.post(Provider.ROOT_URL_CW_NET + "security-groups",
                              headers={"X-Auth-Token": "%s" % token}, data=_body)

                # SSHKey & instance creation
                if imageid not in "Win":
                    _body = '{"keypair":{"name":"cle"}}'
                    request = requests.post(Provider.ROOT_URL_CW + "%s/os-keypairs",
                                            headers={"X-Auth-Token": "%s" % token}, data=_body)
                    data = request.json()
                    key = data['keypair']
                    _body = '{"security_group_rule":{"direction":"ingress","port_range_min":"22",' \
                            '"ethertype":"IPv4","port_range_max":"22","protocol":"tcp","security_group_id":"%s"}}' \
                            % secgroup
                    requests.post(Provider.ROOT_URL_CW_NET + "security-group-rules",
                                  headers={"X-Auth-Token": "%s" % token}, data=_body)
                    _body = '{"server":{"name":"%s","key_name":"%s","imageRef":"%s",' \
                            '"flavorRef":"%s","max_count":%s,"min_count":1,"networks":' \
                            '[{"uuid":"%s"}],"metadata": {"admin_pass": "%s"},"security_groups":' \
                            '[{"name":"default"},{"name":"%s"}]}}' \
                            % (servername, key, imageid, flavorid, number, netid, servpass, secgroup)
                    request = requests.post(Provider.ROOT_URL_CW + "%s/servers" % tenantid,
                                            headers={"X-Auth-Token": "%s" % token}, data=_body)
                    data = request.json()
                    serverid = data['server']['id']
                else:
                    _body = '{"security_group_rule":{"direction":"ingress",' \
                            '"port_range_min":"3389","ethertype":"IPv4",' \
                            '"port_range_max":"3389","protocol":"tcp","security_group_id":"%s"}}' % secgroup
                    request = requests.post(Provider.ROOT_URL_CW + "%s/servers" % tenantid,
                                            headers={"X-Auth-Token": "%s" % token}, data=_body)
                    data = request.json()
                    serverid = data['server']['id']
                # Public Network Interface Id
                request = requests.get(Provider.ROOT_URL_CW_NET + "floatingips",
                                       headers={"X-Auth-Token": "%s" % token})
                data = request.json()
                for i in data['networks']:
                    if "public" in i['name']:
                        netid = i['id']
                # Floatting IP
                _body = '{"floatingip":{"floating_network_id":"%s"}}' % netid
                request = requests.post(Provider.ROOT_URL_CW_NET + "floatingips",
                                        headers={"X-Auth-Token": "%s" % token}, data=_body)
                data = request.json()
                IP = data['floatingip']['floating_ip_address']
                # Commit IP to Server
                _body = '{"addFloatingIp":{"address":"%s"}}' % IP
                requests.post(Provider.ROOT_URL_CW + "%s/servers/%s/action" % (tenantid, serverid),
                              headers={"X-Auth-Token": "%s" % token}, data=_body)
            elif remove:
                requests.delete(Provider.ROOT_URL_CW + "%s/servers/%s" % (tenantid, serverid),
                                headers={"X-Auth-Token": "%s" % token})
            elif reboot:
                requests.post(Provider.ROOT_URL_CW + "%s/servers/%s/reboot" % (tenantid, serverid),
                              headers={"X-Auth-Token": "%s" % token})
            elif rebuild:
                request = requests.get(
                    Provider.ROOT_URL_CW + "%s/servers/%s/detail" % (tenantid, serverid),
                    headers={"X-Auth-Token": "%s" % token})
                data = request.json()
                for i in data['servers']:
                    IP = i['addresses']['private']['addr']
                    imageid = i['image']['id']
                    servername = i['name']

                _body = '{"rebuild": {"imageRef": "%s","name": "%s","adminPass": "%s","accessIPv4": "%s"}}' % (
                    imageid, servername, servpass, IP)
                requests.post(Provider.ROOT_URL_CW + "%s/servers/%s/rebuild" % (tenantid, serverid),
                              headers={"X-Auth-Token": "%s" % token}, data=_body)
            else:
                return 'error'

        @classmethod
        def rackspace(cls, username, apikey, tenantid, image=None, flavor=None, servername=None, serverid=None,
                      rebuild=None, reboot=None, remove=None, insert=None):
            global imageid, flavorid

            _body = '{"auth":{"RAX-KSKEY:apiKeyCredentials":{"username":"%s","apiKey":"%s"}}}' % (username, apikey)
            request = requests.post("https://identity.api.rackspacecloud.com/v2/tokens", data=_body)
            data = request.json()
            token = data['access']['token']['id']

            request = requests.get(Provider.ROOT_URL_RS+"/%s/images" % tenantid,
                                   headers={"Authorization": "Bearer %s" % token})
            data = request.json()
            for i in (data['images']):
                if image in i['name']:
                    imageid = i['id']

            request = requests.get(Provider.ROOT_URL_RS+"/%s/flavors" % tenantid,
                                   headers={"Authorization": "Bearer %s" % token})
            data = request.json()
            for i in (data['flavors']):
                if flavor in i['name']:
                    flavorid = i['id']

            if insert:  # Server Creation
                _body = '{"server": {"name": "%s","imageRef": "%s","flavorRef": "%s"}}' % (
                    servername, imageid, flavorid)
                requests.post(Provider.ROOT_URL_RS + "/v2/%s/servers" % tenantid,
                              headers={"Authorization": "Bearer %s" % token}, data=_body)
            elif remove:
                requests.delete(Provider.ROOT_URL_RS + "v2/%s/servers/%s" % (tenantid, serverid),
                                headers={"Authorization": "Bearer %s" % token})
            elif reboot:
                _body = '{"reboot": {"type": "SOFT"}}'
                requests.post(
                    Provider.ROOT_URL_RS + "v2/%s/servers/%s/reboot" % (tenantid, serverid),
                    data=_body, headers={"Authorization": "Bearer %s" % token})
            elif rebuild:
                _body = '{"server": {"flavorRef": %s,"imageRef": %s,"name": %s,"password_delivery": API}}' % (
                    flavorid, imageid, servername)
                requests.post(Provider.ROOT_URL_RS + "v2/%s/servers/%s" % (tenantid, serverid),
                              data=_body, headers={"Authorization": "Bearer %s" % token})
            else:
                return "error"

        @classmethod
        def digitalocean(cls, token, distribution=None, application=None,
                         region=None, size=None, servername=None, number=None, serverid=None, network=None,
                         rebuild=None, reboot=None, remove=None, insert=None):

            global imageid, SizeId, RegionId, key, imgkey

            key = Provider.Server.generate_rsa(bits=2048)

            _body = '{{"name":"SSH key","public_key":"{0:s}"}}'.format(key)
            requests.post("https://api.digitalocean.com/v2/account/keys",
                          headers={"Authorization": "Bearer %s" % token}, data=_body)
            request = requests.get("https://api.digitalocean.com/v2/account/keys",
                                   headers={"Authorization": "Bearer %s" % token})
            data = request.json()
            keyid = data['ssh_keys']['id']
            # global KeyId
            if distribution is not None:
                request = requests.get("https://api.digitalocean.com/v2/images",
                                       headers={"Authorization": "Bearer %s" % token})
                data = request.json()
                if distribution.split()[2] is not None:
                    imgkey = distribution.split()[0] + "-" + distribution.split()[1] + "-" + distribution.split()[2]
                elif distribution.split()[2] is None:
                    imgkey = distribution.split()[0] + "-" + distribution.split()[1] + "-"
                else:
                    imgkey = "coreos-beta"

                for i in data['images']:
                    if imgkey in i['slug']:
                        imageid = i['id']

            elif application is not None:
                request = requests.get(Provider.ROOT_URL_DO + "/images",
                                       headers={"Authorization": "Bearer %s" % token})
                data = request.json()
                for i in data['application']:
                    if application in i:
                        imageid = i['id']

            request = requests.get(Provider.ROOT_URL_DO + "/sizes",
                                   headers={"Authorization": "Bearer %s" % token})
            data = request.json()
            for i in data['sizes']:
                if size in i['slug'] and "True" in i['available']:
                    SizeId = i['slug']

            request = requests.get(Provider.ROOT_URL_DO + "/regions",
                                   headers={"Authorization": "Bearer %s" % token})
            data = request.json()
            for i in data['regions']:
                if region in i['slug'] and "True" in i['available']:
                    RegionId = i['slug']

            if insert:
                if network is None and number is None:
                    _body = '{"name": %s,"region": "%s","size": "%s","image": "%s","ssh_keys": "%s",' \
                            '"backups": false,"ipv6": ' \
                            'true,"user_data": null,"private_networking": null}'\
                            % (servername, region, size, imageid, keyid)
                elif network is None and number is not None:
                    i = 0
                    n1 = ""
                    while i != (int(number)-1):
                        n1 += '"'+servername + str(i)+'"'+", "
                        _body = '{"name": [%s, "%s"],"region": "%s","size": "%s","image": "%s","ssh_keys": "%s",' \
                            '"backups": false,"ipv6": ' \
                            'true,"user_data": null,"private_networking": null}' \
                                % (n1, servername+str(i+1), region, size, imageid, keyid)
                elif network is not None and number is None:
                    _body = '{"name": "%s","region": "%s","size": "%s","image": "%s","ssh_keys": "%s",' \
                            '"backups": false,"ipv6": ' \
                            'true,"user_data": null,"private_networking": true}' \
                            % (servername, region, size, imageid, keyid)
                else:
                    i = 0
                    n1 = ""
                    while i != (int(number)-1):
                        n1 += '"'+servername + str(i)+'"'+", "
                        _body = '{"name": [%s, "%s"],"region": "%s","size": "%s","image": "%s","ssh_keys": "%s",' \
                            '"backups": false,"ipv6": ' \
                            'true,"user_data": null,"private_networking": true}' \
                                % (n1, servername+str(i+1), region, size, imageid, keyid)
                requests.post(Provider.ROOT_URL_DO + "/droplets",
                              headers={"Authorization": "Bearer %s" % token},
                              data=_body)
            elif remove:
                requests.delete(Provider.ROOT_URL_DO + "/droplets/%s" % serverid,
                                headers={"Authorization": "Bearer %s" % token})
            elif reboot:
                _body = '{"type":"reboot"}'
                requests.post(Provider.ROOT_URL_DO + "/droplets/%s" % serverid,
                              headers={"Authorization": "Bearer %s" % token}, data=_body)
            elif rebuild:
                request = requests.get(Provider.ROOT_URL_DO + "/images",
                                       headers={"Authorization": "Bearer %s" % token})
                data = request.json()
                for i in data['images']:
                    if distribution in i['slug']:
                        imageid = i['id']
                _body = '{"type":"rebuild","image":"%s"}' % imageid
                requests.post(Provider.ROOT_URL_DO + "/droplets/%s/actions" % serverid,
                              headers={"Authorization": "Bearer %s" % token}, data=_body)
            else:
                return 'error'

        @classmethod
        def google(cls, project, token, image=None, region=None, size=None, serverid=None, servername=None,
                   template=None, reboot=None, remove=None, insert=None):

            keyid = Provider.Server.generate_rsa(bits=2048)

            global RegionId, imageid, SizeId
            request = requests.get(
                Provider.ROOT_URL_GO+"/%s/%s-cloud/global/images" % (project, image),
                header={"Authorization": "Bearer %s" % token})
            data = request.json()
            for i in data['items']:
                if image in i['selfLink']:
                    imageid = i['selfLink'][-1]

            zones = "asia", "europe", "us-central", "us-east"
            if region not in zones:
                raise Exception("Zone error")
            else:
                request = requests.get(Provider.ROOT_URL_GO+"/%s/regions" % project,
                                       header={"Authorization": "Bearer %s" % token})
                data = request.json()
                for i in data['items']:
                    if region in i['items']:
                        RegionId = i['selfLink']

            request = requests.get(
                "https://www.googleapis.com/compute/v1/projects/%s/zones/%s/machineType" % (project, RegionId),
                header={"Authorization": "Bearer %s" % token})
            data = request.json()
            for i in data['items']:
                if size in i['items']:
                    SizeId = i['selfLink']

            if insert:
                if "Windows" not in image:
                    _body = '{"name": "%s","machineType": "%s",' \
                            '"metadata": { "items": [ { "key": "ssh-keys", "value": "%s" } ] },' \
                            '"networkInterfaces": [{"accessConfigs": ' \
                            '[{"type": "ONE_TO_ONE_NAT","name": "External NAT"}],' \
                            '"network": "global/networks/default"}],''"disks": [{"autoDelete": "true","boot": "true",' \
                            '"type": "PERSISTENT","initializeParams": ''{"sourceImage": "%s"}}]}' \
                            % (servername, keyid, SizeId, imageid)
                else:
                    _body = '{"name": "%s","machineType": "%s","networkInterfaces": [{"accessConfigs":' \
                            ' [{"type": "ONE_TO_ONE_NAT","name": "External NAT"}],' \
                            '"network": "global/networks/default"}],"disks": [{"autoDelete": "true",' \
                            '"boot": "true","type": "PERSISTENT","initializeParams": {"sourceImage": "%s"}}]}' \
                            % (servername, SizeId, imageid)

                if template is None:
                    url = Provider.ROOT_URL_GO + "%s/zones/%s/instances" % (project, region)
                else:
                    url = Provider.ROOT_URL_GO + "%s/global/instanceTemplates" % project

                requests.post(url, header={"Authorization": "Bearer %s" % token}, data=_body)

            elif remove:
                requests.delete(Provider.ROOT_URL_GO + "%s/zones/%s/instances/%s" % (
                    project, RegionId, serverid), header={"Authorization": "Bearer %s" % token})
            elif reboot:
                requests.post(Provider.ROOT_URL_GO + "%s/zones/%s/instances/%s/reset" % (
                    project, RegionId, serverid), header={"Authorization": "Bearer %s" % token})
            else:
                return "error"

        @classmethod
        def amazon(cls, accesskey, secretkey, serverid=None, image=None, number=None, sshkey=None, reboot=None,
                   remove=None, insert=None):

            connect = boto.connect_ec2(aws_access_key_id=accesskey, aws_secret_access_key=secretkey)

            group = connect.create_security_group(name="SecGroup")
            group.authorize('tcp', 22, 22, '0.0.0.0/0')
            group.authorize('tcp', 3389, 3389, '0.0.0.0/0')

            if insert:
                if "Windows" not in connect.get_image(image_id=image).platform:
                    connect.create_key_pair(key_name=sshkey)
                    connect.run_instances(image_id=image, min_count=1, max_count=number, instance_type='m1.small',
                                          security_groups=group, key_name=key)
                else:
                    connect.run_instances(image_id=image, min_count=1, max_count=number, instance_type='m1.small',
                                          security_groups=group)
            elif remove:
                connect.terminate_instances(instance_ids=serverid)
            elif reboot:
                connect.stop_instances(instance_ids=serverid)
            else:
                return "error"

        @classmethod
        def ovh(cls, applicationkey, secretkey, endpoint, region=None, image=None, flavor=None, servername=None,
                serverid=None, keyname=None, rebuild=None, reboot=None, remove=None, insert=None):
            global time, flavorid, imageid

            keyid = Provider.Server.generate_rsa(bits=2048)

            client = ovh.Client(application_key=applicationkey, application_secret=secretkey, endpoint=endpoint)
            ck = client.new_consumer_key_request()
            consumerkey = (ck.request())['consumerKey']
            d = requests.get("https://eu.api.ovh.com/1.0/auth/time")
            for i in d:
                time = i

            s1 = hashlib.sha1()
            s1.update("+".join([applicationkey, consumerkey, "GET", "https://eu.api.ovh.com/1.0/cloud/project", time]))
            sig = "$1$" + s1.hexdigest()
            queryheaders = {"X-Ovh-Application": applicationkey, "X-Ovh-Timestamp": time, "X-Ovh-Consumer": consumerkey,
                            "X-Ovh-Signature": sig, "Content-type": "application/json"}
            service = requests.post("https://eu.api.ovh.com/1.0/cloud/project", headers=queryheaders)

            s1 = hashlib.sha1()
            s1.update("+".join(
                [applicationkey, consumerkey, "GET", Provider.ROOT_URL_OVH + "cloud/project/%s/image" % service,
                 time]))
            sig = "$1$" + s1.hexdigest()
            queryheaders = {"X-Ovh-Application": applicationkey, "X-Ovh-Timestamp": time, "X-Ovh-Consumer": consumerkey,
                            "X-Ovh-Signature": sig, "Content-type": "application/json"}
            request = requests.get(Provider.ROOT_URL_OVH + "cloud/project/%s/image" % service, headers=queryheaders)
            data = request.json()
            for i in data:
                if image in i['name'] and endpoint in i['Region']:
                    imageid = i['id']

            # Get FlavorId
            s1 = hashlib.sha1()
            s1.update("+".join(
                [applicationkey, consumerkey, "GET", Provider.ROOT_URL_OVH + "cloud/project/%s/flavor" % service,
                 time]))
            sig = "$1$" + s1.hexdigest()
            queryheaders = {"X-Ovh-Application": applicationkey, "X-Ovh-Timestamp": time, "X-Ovh-Consumer": consumerkey,
                            "X-Ovh-Signature": sig, "Content-type": "application/json"}
            request = requests.get(Provider.ROOT_URL_OVH + "cloud/project/%s/flavor" % service, headers=queryheaders)
            data = request.json()
            for i in data:
                if flavor in i['name'] and endpoint in i['region']:
                    flavorid = i['id']

            # Instance actions
            if insert:
                if "Windows" not in image:
                    s1 = hashlib.sha1()
                    s1.update("+".join([applicationkey, consumerkey, "GET",
                                        Provider.ROOT_URL_OVH + "cloud/project/%s/instance" % service, time]))
                    sig = "$1$" + s1.hexdigest()
                    queryheaders = {"X-Ovh-Application": applicationkey, "X-Ovh-Timestamp": time,
                                    "X-Ovh-Consumer": consumerkey, "X-Ovh-Signature": sig,
                                    "Content-type": "application/json"}
                    _body = '{"name": "%s","publicKey": "%s","region": "%s"}' % (keyname, keyid, region)
                    data = requests.post(Provider.ROOT_URL_OVH+"cloud/project/%s/sshkey" % service,
                                         headers=queryheaders, body=_body)
                    res = data.json()
                    sshkey = res['id']
                    _body = '{"flavorId": %s,"imageId": "%s","monthlyBilling": false,"name": "%s","region": "%s",' \
                            '"sshKeyId": "%s}' % (flavorid, imageid, servername, region, sshkey)
                else:
                    _body = '{"flavorId": %s,"imageId": "%s","monthlyBilling": false,"name": "%s","region": "%s"}' % (
                        flavorid, imageid, servername, region)
                s1 = hashlib.sha1()
                s1.update("+".join([applicationkey, consumerkey, "GET",
                                    Provider.ROOT_URL_OVH + "cloud/project/%s/instance" % service, time]))
                sig = "$1$" + s1.hexdigest()
                queryheaders = {"X-Ovh-Application": applicationkey, "X-Ovh-Timestamp": time,
                                "X-Ovh-Consumer": consumerkey, "X-Ovh-Signature": sig,
                                "Content-type": "application/json"}
                requests.post(Provider.ROOT_URL_OVH + "cloud/project/%s/instance" % service, headers=queryheaders,
                              body=_body)
            elif remove:
                s1 = hashlib.sha1()
                s1.update("+".join([applicationkey, consumerkey, "GET",
                                    Provider.ROOT_URL_OVH + "cloud/project/%s/instance" % service, time]))
                sig = "$1$" + s1.hexdigest()
                queryheaders = {"X-Ovh-Application": applicationkey, "X-Ovh-Timestamp": time,
                                "X-Ovh-Consumer": consumerkey, "X-Ovh-Signature": sig,
                                "Content-type": "application/json"}
                requests.delete(Provider.ROOT_URL_OVH + "cloud/project/%s/instance/%s" % (service, serverid),
                                headers=queryheaders)
            elif reboot:
                s1 = hashlib.sha1()
                s1.update("+".join([applicationkey, consumerkey, "GET",
                                    Provider.ROOT_URL_OVH + "cloud/project/%s/instance" % service, time]))
                sig = "$1$" + s1.hexdigest()
                queryheaders = {"X-Ovh-Application": applicationkey, "X-Ovh-Timestamp": time,
                                "X-Ovh-Consumer": consumerkey, "X-Ovh-Signature": sig,
                                "Content-type": "application/json"}
                requests.post(Provider.ROOT_URL_OVH + "cloud/project/%s/instance/%s/reboot" % (service, serverid),
                              headers=queryheaders)
            elif rebuild:
                s1 = hashlib.sha1()
                s1.update("+".join([applicationkey, consumerkey, "GET",
                                    Provider.ROOT_URL_OVH + "cloud/project/%s/instance" % service, time]))
                sig = "$1$" + s1.hexdigest()
                queryheaders = {"X-Ovh-Application": applicationkey, "X-Ovh-Timestamp": time,
                                "X-Ovh-Consumer": consumerkey, "X-Ovh-Signature": sig,
                                "Content-type": "application/json"}
                requests.post(Provider.ROOT_URL_OVH + "cloud/project/%s/instance/%s/reinstall" % (service, serverid),
                              headers=queryheaders)

        @classmethod
        def aruba(cls, dc, username, password, servertype=None, flavor=None, servername=None,
                  servpass=None, image=None, number=None, serverid=None,
                  cpu=None, ram=None, disk=None, token=None, insert=None, reboot=None, remove=None, rebuild=None):

            if insert:
                global templ, image_id, i
                if dc in range(1, 6, 1):
                    token = CloudInterface(dc=dc)

                if None in servertype:
                    templ = token.find_template(hv=4)
                elif "lowcost" in servertype:
                    templ = token.find_template(hv=3)
                elif "vmware" in servertype:
                    templ = token.find_template(hv=2)
                elif "hyperv" in servertype:
                    templ = token.find_template(hv=1)

                for t in templ:
                    if image in t.id_code and "True" in t.enabled:
                        image_id = t.template_id
                        return image_id

                size = {"small", 'medium', 'large', 'extra large'}
                for i in size:
                    if flavor not in i:
                        Exception("size error")
                    else:
                        return i

                token.login(username=username, password=password, load=True)
                if servertype is None:
                    if number is None:
                        c = SmartVmCreator(name=servername, admin_password=servpass,
                                           template_id=image_id, auth_obj=token.auth)
                        c.set_type(size=i)
                        c.commit(url=token.wcf_baseurl, debug=True)
                    else:
                        a = 0
                        while a < int(number):
                            a += 1
                            c = SmartVmCreator(name=servername + a, admin_password=servpass,
                                               template_id=image_id, auth_obj=token.auth)
                            c.set_type(size=i)
                            c.commit(url=token.wcf_baseurl, debug=True)
                else:
                    if number is None:
                        ip = token.purchase_ip()
                        pvm = ProVmCreator(name=servername, admin_password=servpass,
                                           template_id=image_id, auth_obj=token.auth)
                        pvm.set_cpu_qty(int(cpu))
                        pvm.set_ram_qty(int(ram))
                        pvm.add_virtual_disk(int(disk))
                        pvm.add_public_ip(public_ip_address_resource_id=ip.resid, primary_ip_address=True)
                        pvm.commit(url=token.wcf_baseurl, debug=True)
                        time.sleep(60)
                    else:
                        a = 0
                        while a < int(number):
                            a += 1
                            ip = token.purchase_ip()
                            pvm = ProVmCreator(name=servername + a, admin_password=servpass,
                                               template_id=image_id, auth_obj=token.auth)
                            pvm.set_cpu_qty(int(cpu))
                            pvm.set_ram_qty(int(ram))
                            pvm.add_virtual_disk(int(disk))
                            pvm.add_public_ip(public_ip_address_resource_id=ip.resid, primary_ip_address=True)
                            pvm.commit(url=token.wcf_baseurl, debug=True)
                            time.sleep(60)
            elif reboot:
                token = CloudInterface(dc=dc)
                token.login(username=username, password=password, load=True)
                token.poweroff_server(server_id=serverid)
                time.sleep(60)
                token.poweron_server(server_id=serverid)
            elif remove:
                token = CloudInterface(dc=dc)
                token.login(username=username, password=password, load=True)
                token.poweroff_server(server_id=serverid)
                time.sleep(60)
                token.delete_vm(server_id=serverid)
            elif rebuild:
                token = CloudInterface(dc=dc)
                token.login(username=username, password=password, load=True)
                for vm in token.get_vm(pattern=serverid):
                    vm.poweroff()
                    time.sleep(60)
                    vm.reinitialize(admin_password=servpass)
