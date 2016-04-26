import boto
import requests
import ovh
import hashlib


class Provider(object):
    @classmethod
    class Server(object):
        @classmethod
        def Numergy(cls, AccessKey, SecretKey, TenantId, Image, App, Flavor, ServerName, ServerId, action):
            global ImageId, FlavorId, _version
            request = requests.get("https://api2.numergy.com/")
            data = request.json()
            for i in (data['versions']['version']):
                if "CURRENT" in i['status']:
                    _version = i['id']

            body = '{"auth": {"apiAccessKeyCredentials": {"accessKey": "%s","secretKey": "%s" },"tenantId": "%s"}}' % (
                AccessKey, SecretKey, TenantId)
            request = requests.post("https://api2.numergy.com/%s/tokens" % _version, data=body)
            data = request.json()
            _token = (data['access']['token']['id'])

            request = requests.get("https://api2.numergy.com/%s/%s/images" % (_version, TenantId),
                                   headers={"X-Auth-Token": "%s" % _token})
            data = request.json()

            if "Windows" in Image:
                if App is None:
                    ImgKey = ''.join((list(Image.split()[0])[:3])) + Image.split()[1] + " " + Image.split()[2] + " " + \
                             Image.split()[3] + " " + Image.split()[4]
                else:
                    ImgKey = ''.join((list(Image.split()[0])[:3])) + Image.split()[1] + " " + Image.split()[
                        2] + " " + App
            else:
                if App is not None:
                    ImgKey = ''.join((list(Image.split()[0])[:3])) + Image.split()[-1] + " " + App
                else:
                    ImgKey = ''.join((list(Image.split()[0])[:3])) + Image.split()[-1]

            for i in (data['images']):
                if ImgKey in i['name']:
                    ImageId = i['id']

            request = requests.get("https://api2.numergy.com/%s/%s/images" % (_version, TenantId),
                                   headers={"X-Auth-Token": "%s" % _token})
            data = request.json()
            for i in (data["flavors"]):
                if Flavor in i["name"]:
                    FlavorId = i['id']

            if action.get("Insert"):
                _body = '{"server": {"flavorRef": %s,"imageRef": %s,"name": %s,"password_delivery": API}}' % (
                    FlavorId, ImageId, ServerName)
                requests.post("https://api2.numergy.com/%s/%s/servers" % (_version, TenantId),
                              headers={"X-Auth-Token": "%s" % _token}, data=_body)
            elif action.get("Reboot"):
                _body = '{"reboot": {"type": "SOFT"}}'
                requests.post(
                    "https://compute.fr1.cloudwatt.com/%s/%s/servers/%s/reboot" % (_version, TenantId, ServerId),
                    data=_body, headers={"X-Auth-Token": "%s" % _token})
            elif action.get("Remove"):
                requests.delete("https://compute.fr1.cloudwatt.com/%s/%s/servers/%s" % (_version, TenantId, ServerId),
                                headers={"X-Auth-Token": "%s" % _token})
            elif action.get("Rebuild"):
                _body = '{"server": {"flavorRef": %s,"imageRef": %s,"name": %s,"password_delivery": API}}' % (
                    FlavorId, ImageId, ServerName)
                requests.post("https://api2.numergy.com/%s/%s/servers/%s" % (_version, TenantId, ServerId),
                              headers={"X-Auth-Token": "%s" % _token}, data=_body)
            else:
                return 'error'

        @classmethod
        def Cloudwatt(cls, Username, Password, TenantId, Image, Flavor, ServerId, ServerName, Number, ServPass, action):
            global ImageId, IP, FlavorId
            _body = "<?xml version='1.0' encoding='UTF-8'?><auth xmlns='http://docs.openstack.org/identity/v2.0' tenantName='%s'><passwordCredentials username='%s' password='%s'/></auth>" % (
                TenantId, Username, Password)
            request = requests.post("https://identity.fr1.cloudwatt.com/v2/tokens", data=_body)
            data = request.json()
            token = data['access']['token']['id']

            request = requests.get("https://compute.fr1.cloudwatt.com/v2/%s/images" % TenantId,
                                   headers={"X-Auth-Token": "%s" % (token)})
            data = request.json()
            for i in (data['images']):
                if Image in i['name']:
                    ImageId = i['id']

            request = requests.get("https://compute.fr1.cloudwatt.com/v2/%s/flavors" % TenantId,
                                   headers={"X-Auth-Token": "%s" % token})
            data = request.json()
            for i in (data['flavors']):
                if Flavor in i['name']:
                    FlavorId = i['id']

            if action.get("insert"):
                ## Get Security Group
                _body = '{"security_group":{"name":"Security","description":"SecGroup"}}'
                request = requests.post("https://network.fr1.cloudwatt.com/v2/security-groups",
                                        headers={"X-Auth-Token": "%s" % token}, data=_body)
                data = request.json()
                SecGroup = data['security_group']['name']
                ## Get Network Id
                _body = '{"network":{"name": "network1", "admin_state_up": true}}'
                request = requests.post("https://network.fr1.cloudwatt.com/v2/security-groups",
                                        headers={"X-Auth-Token": "%s" % token}, data=_body)
                data = request.json
                NetId = data['network']['id']
                _body = '{"subnet":{"network_id":"%s","ip_version":4,"cidr":"192.168.0.0/24"}}' % (NetId)
                requests.post("https://network.fr1.cloudwatt.com/v2/security-groups",
                              headers={"X-Auth-Token": "%s" % token}, data=_body)

                ## SSHKey & instance creation
                if ImageId not in "Win":
                    _body = '{"keypair":{"name":"cle"}}'
                    request = requests.post("https://network.fr1.cloudwatt.com/v2/%s/os-keypairs",
                                            headers={"X-Auth-Token": "%s" % token}, data=_body)
                    data = request.json()
                    Key = data['keypair']
                    _body = '{"security_group_rule":{"direction":"ingress","port_range_min":"22","ethertype":"IPv4","port_range_max":"22","protocol":"tcp","security_group_id":"%s"}}' % (
                        SecGroup)
                    requests.post("https://network.fr1.cloudwatt.com/v2/security-group-rules",
                                  headers={"X-Auth-Token": "%s" % token}, data=_body)
                    _body = '{"server":{"name":"%s","key_name":"cle","imageRef":"%s","flavorRef":"%s","max_count":%s,"min_count":1,"networks":[{"uuid":"%s"}],"metadata": {"admin_pass": "%s"},"security_groups":[{"name":"default"},{"name":"%s"}]}}' % (
                        ServerName, ImageId, FlavorId, Number, NetId, ServPass, SecGroup)
                    request = requests.post("https://compute.fr1.cloudwatt.com/v2/%s/servers" % TenantId,
                                            headers={"X-Auth-Token": "%s" % token}, data=_body)
                    data = request.json()
                    ServerId = data['server']['id']
                else:
                    _body = '{"security_group_rule":{"direction":"ingress","port_range_min":"3389","ethertype":"IPv4","port_range_max":"3389","protocol":"tcp","security_group_id":"%s"}}' % (
                        SecGroup)
                    request = requests.post("https://compute.fr1.cloudwatt.com/v2/%s/servers" % TenantId,
                                            headers={"X-Auth-Token": "%s" % token}, data=_body)
                    data = request.json()
                    ServerId = data['server']['id']
                ## Public Network Interface Id
                request = requests.get("https://network.fr1.cloudwatt.com/v2/networks",
                                       headers={"X-Auth-Token": "%s" % token})
                data = request.json()
                for i in data['networks']:
                    if "public" in i['name']:
                        NetId = i['id']
                ## Floatting IP
                _body = '{"floatingip":{"floating_network_id":"%s"}}' % NetId
                request = requests.post("https://network.fr1.cloudwatt.com/v2/floatingips",
                                        headers={"X-Auth-Token": "%s" % token}, data=_body)
                data = request.json()
                IP = data['floatinip']['floating_ip_address']
                ## Commit IP to Server
                _body = '{"addFloatingIp":{"address":"%s"}}' % IP
                requests.post("https://compute.fr1.cloudwatt.com/v2/%s/servers/%s/action" % (TenantId, ServerId),
                              headers={"X-Auth-Token": "%s" % token}, data=_body)
            elif action.get("Remove"):
                requests.delete("https://compute.fr1.cloudwatt.com/v2/%s/servers/%s" % (TenantId, ServerId),
                                headers={"X-Auth-Token": "%s" % token})
            elif action.get("Reboot"):
                requests.post("https://compute.fr1.cloudwatt.com/v2/%s/servers/%s/reboot" % (TenantId, ServerId),
                              headers={"X-Auth-Token": "%s" % token})
            elif action.get("Rebuild"):
                request = requests.get(
                    "https://compute.fr1.cloudwatt.com/v2/%s/servers/%s/detail" % (TenantId, ServerId),
                    headers={"X-Auth-Token": "%s" % token})
                data = request.json()
                for i in data['servers']:
                    IP = i['addresses']['private']['addr']
                    ImageId = i['image']['id']
                    ServerName = i['name']

                _body = '{"rebuild": {"imageRef": "%s","name": "%s","adminPass": "%s","accessIPv4": "%s"}}' % (
                    ImageId, ServerName, ServPass, IP)
                requests.post("https://compute.fr1.cloudwatt.com/v2/%s/servers/%s/rebuild" % (TenantId, ServerId),
                              headers={"X-Auth-Token": "%s" % token}, data=_body)
            else:
                return ('error')

        @classmethod
        def Rackspace(cls, username, apikey, TenantId, Image, Flavor, ServerName, ServerId, action):
            global ImageId, FlavorId, version
            request = requests.get("https://compute.fr1.cloudwatt.com/")
            data = request.json()
            for i in (data['version']['version']):
                if "2" in i['id']:
                    version = i['id']

            _body = '{"auth":{"RAX-KSKEY:apiKeyCredentials":{"username":"%s","apiKey":"%s"}}}' % (username, apikey)
            request = requests.post("https://identity.api.rackspacecloud.com/%s/tokens" % version, data=_body)
            data = request.json()
            Token = data['access']['token']['id']

            request = requests.get("https://lon.servers.api.rackspacecloud.com/v2/%s/images" % TenantId,
                                   headers={"Authorization": "Bearer %s" % Token})
            data = request.json()
            for i in (data['images']):
                if Image in i['name']:
                    ImageId = i['id']

            request = requests.get("https://lon.servers.api.rackspacecloud.com/v2/%s/flavors" % TenantId,
                                   headers={"Authorization": "Bearer %s" % Token})
            data = request.json()
            for i in (data['flavors']):
                if Flavor in i['name']:
                    FlavorId = i['id']

            if action.get("insert"):  ## Server Creation
                _body = '{"server": {"name": "%s","imageRef": "%s","flavorRef": "%s"}}' % (
                    ServerName, ImageId, FlavorId)
                requests.post("https://lon.servers.api.rackspacecloud.com/v2/%s/servers" % TenantId,
                              headers={"Authorization": "Bearer %s" % Token}, data=_body)
            elif action.get("Remove"):
                requests.delete("https://lon.servers.api.rackspacecloud.com/v2/%s/servers/%s" % (TenantId, ServerId),
                                headers={"Authorization": "Bearer %s" % Token})
            elif action.get("Reboot"):
                _body = '{"reboot": {"type": "SOFT"}}'
                requests.post(
                    "https://lon.servers.api.rackspacecloud.com/v2/%s/servers/%s/reboot" % (TenantId, ServerId),
                    data=_body, headers={"Authorization": "Bearer %s" % Token})
            elif action.get("Rebuild"):
                _body = '{"server": {"flavorRef": %s,"imageRef": %s,"name": %s,"password_delivery": API}}' % (
                    FlavorId, ImageId, ServerName)
                requests.post("https://lon.servers.api.rackspacecloud.com/v2/%s/servers/%s" % (TenantId, ServerId),
                              data=_body, headers={"Authorization": "Bearer %s" % Token})
            else:
                return ("error")

        @classmethod
        def DigitalOcean(cls, Token, Distribution, Application, Region, Size, ServerName, ServerId, action):
            global ImageId, SizeId, RegionId, Key

            def generate_RSA(bits=2048):
                '''
                Generate an RSA keypair with an exponent of 65537 in PEM format
                param: bits The key length in bits
                Return private key and public key
                '''
                from Crypto.PublicKey import RSA
                new_key = RSA.generate(bits, e=65537)
                public_key = new_key.publickey().exportKey("PEM")
                private_key = new_key.exportKey("PEM")
                return private_key, public_key

            Key = generate_RSA(bits=2048)

            _body = '{"name":"SSH key","public_key":"%s"}' % Key
            requests.post("https://api.digitalocean.com/v2/account/keys",
                          headers={"Authorization": "Bearer %s" % Token}, data=_body)
            data = requests.get("https://api.digitalocean.com/v2/account/keys",
                                headers={"Authorization": "Bearer %s" % Token})
            KeyId = data['ssh_keys']['id']
            # global KeyId
            if Distribution is not None:
                request = requests.get("https://api.digitalocean.com/v2/images",
                                       headers={"Authorization": "Bearer %s" % Token})
                data = request.json()
                if Distribution.split()[2] is not None:
                    Imgkey = Distribution.split()[0] + "-" + Distribution.split()[1] + "-" + Distribution.split()[2]
                elif Distribution.split()[2] is None:
                    Imgkey = Distribution.split()[0] + "-" + Distribution.split()[1] + "-"
                else:
                    Imgkey = "coreos-beta"

                for i in data['images']:
                    if Imgkey in i['slug']:
                        ImageId = i['id']

            elif Application is not None:
                request = requests.get("https://api.digitalocean.com/v2/images",
                                       headers={"Authorization": "Bearer %s" % Token})
                data = request.json()
                for i in data['application']:
                    if Application in i:
                        ImageId = i['id']

            request = requests.get("https://api.digitalocean.com/v2/sizes",
                                   headers={"Authorization": "Bearer %s"} % Token)
            data = request.json()
            for i in data['sizes']:
                if Size in i['slug'] and "True" in i['available']:
                    SizeId = i['slug']

            request = requests.get("https://api.digitalocean.com/v2/regions",
                                   headers={"Authorization": "Bearer %s"} % Token)
            data = request.json()
            for i in data['regions']:
                if Region in i['slug'] and "True" in i['available']:
                    RegionId = i['slug']

            if action.get("insert"):
                _body = '{"name": "%s","region": "%s","size": "%s","image": "%s","ssh_keys": "%s","backups": false,"ipv6": true,"user_data": null,"private_networking": null}' % (
                    ServerName, RegionId, SizeId, ImageId, KeyId)
                requests.post("https://api.digitalocean.com/v2/droplets",
                              headers={"Authorization": "Bearer %s"} % Token,
                              data=_body)
            elif action.get("Remove"):
                requests.delete("https://api.digitalocean.com/v2/droplets/%s" % ServerId,
                                headers={"Authorization": "Bearer %s"} % Token)
            elif action.get("Reboot"):
                _body = '{"type":"reboot"}'
                requests.post("https://api.digitalocean.com/v2/droplets/%s" % ServerId,
                              headers={"Authorization": "Bearer %s"} % Token, data=_body)
            elif action.get("Rebuild"):
                request = requests.get("https://api.digitalocean.com/v2/images",
                                       headers={"Authorization": "Bearer %s"} % Token)
                data = request.json()
                for i in data['images']:
                    if Distribution in i['slug']:
                        ImageId = i['id']
                _body = '{"type":"rebuild","image":"%s"}' % ImageId
                requests.post("https://api.digitalocean.com/v2/droplets/%s/actions" % ServerId,
                              headers={"Authorization": "Bearer %s"} % Token, data=_body)
            else:
                return 'error'

        @classmethod
        def Google(cls, Image, Project, Token, Region, Size, ServerId, ServerName, action):

            global RegionId, ImageId, SizeId
            request = requests.get(
                "https://www.googleapis.com/compute/v1/projects/%s/%s-cloud/global/images" % (Project, Image),
                header={"Authorization": "Bearer %s"} % Token)
            data = request.json()
            for i in data['items']:
                if Image in data['selfLink']:
                    ImageId = data['selfLink'][-1]

            request = requests.get("https://www.googleapis.com/compute/v1/projects/%s/regions" % (Project),
                                   header={"Authorization": "Bearer %s"} % Token)
            data = request.json()
            for i in data['items']:
                if Region in data['items']:
                    RegionId = data['selfLink']

            request = requests.get(
                "https://www.googleapis.com/compute/v1/projects/%s/zones/%s/machineType" % (Project, RegionId),
                header={"Authorization": "Bearer %s"} % Token)
            data = request.json()
            for i in data['items']:
                if Size in data['items']:
                    SizeId = data['selfLink']

            if action.get("Insert"):
                _body = '{"name": "%s","machineType": "%s","networkInterfaces": [{"accessConfigs": [{"type": "ONE_TO_ONE_NAT","name": "External NAT"}],"network": "global/networks/default"}],"disks": [{"autoDelete": "true","boot": "true","type": "PERSISTENT","initializeParams": {"sourceImage": "%s"}}]}' % (
                    ServerName, SizeId, ImageId)
                requests.post(
                    "https://www.googleapis.com/compute/v1/projects/%s/zones/%s/instances" % (Project, RegionId),
                    header={"Authorization": "Bearer %s"} % Token, data=_body)

            elif action.get("Remove"):
                requests.delete("https://www.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s" % (
                    Project, RegionId, ServerId), header={"Authorization": "Bearer %s"} % Token)
            elif action.get("Reboot"):
                requests.post("https://www.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s/reset" % (
                    Project, RegionId, ServerId), header={"Authorization": "Bearer %s"} % Token)
            else:
                return "error"

        @classmethod
        def Amazon(cls, AccessKey, SecretKey, ImageId, Number, ServerId, action):

            connect = boto.connect_ec2(aws_access_key_id=AccessKey, aws_secret_access_key=SecretKey)

            group = connect.create_security_group(name="SecGroup")
            group.authorize('tcp', 22, 22, '0.0.0.0/0')
            group.authorize('tcp', 3389, 3389, '0.0.0.0/0')

            if action.get("insert"):
                connect.run_instances(ImageId, min_count=1, max_count=Number, instance_type='m1.small',
                                      security_groups=group)
            elif action.get("Remove"):
                connect.terminate_instances(instance_ids=ServerId)
            elif action.get("Reboot"):
                connect.stop_instances(instance_ids=ServerId)
            else:
                return "error"

        @classmethod
        def OVH(cls, ApplicationKey, SecretKey, EndPoint, Region, Image, Flavor, ServerName, ServerId, action):
            global time, FlavorId, ImageId
            client = ovh.Client(application_key=ApplicationKey, application_secret=SecretKey, endpoint=EndPoint)
            ck = client.new_consumer_key_request()
            ConsumerKey = (ck.request())['consumerKey']
            d = requests.get("https://eu.api.ovh.com/1.0/auth/time")
            for i in d:
                time = i

            s1 = hashlib.sha1()
            s1.update("+".join([ApplicationKey, ConsumerKey, "GET", "https://eu.api.ovh.com/1.0/cloud/project", time]))
            sig = "$1$" + s1.hexdigest()
            queryHeaders = {"X-Ovh-Application": ApplicationKey, "X-Ovh-Timestamp": time, "X-Ovh-Consumer": ConsumerKey,
                            "X-Ovh-Signature": sig, "Content-type": "application/json"}
            service = requests.post("https://eu.api.ovh.com/1.0/cloud/project", headers=queryHeaders)

            s1 = hashlib.sha1()
            s1.update("+".join(
                [ApplicationKey, ConsumerKey, "GET", "https://eu.api.ovh.com/1.0/cloud/project/%s/image" % service,
                 time]))
            sig = "$1$" + s1.hexdigest()
            queryHeaders = {"X-Ovh-Application": ApplicationKey, "X-Ovh-Timestamp": time, "X-Ovh-Consumer": ConsumerKey,
                            "X-Ovh-Signature": sig, "Content-type": "application/json"}
            image = requests.get("https://eu.api.ovh.com/1.0/cloud/project/%s/image" % service, headers=queryHeaders)
            for i in image:
                if Image in i['name'] and EndPoint in i['Region']:
                    ImageId = i['id']

            # Get FlavorId
            s1 = hashlib.sha1()
            s1.update("+".join(
                [ApplicationKey, ConsumerKey, "GET", "https://eu.api.ovh.com/1.0/cloud/project/%s/flavor" % service,
                 time]))
            sig = "$1$" + s1.hexdigest()
            queryHeaders = {"X-Ovh-Application": ApplicationKey, "X-Ovh-Timestamp": time, "X-Ovh-Consumer": ConsumerKey,
                            "X-Ovh-Signature": sig, "Content-type": "application/json"}
            flavor = requests.get("https://eu.api.ovh.com/1.0/cloud/project/%s/flavor" % service, headers=queryHeaders)
            for i in flavor:
                if Flavor in i['name'] and EndPoint in i['region']:
                    FlavorId = i['id']

            # Instance actions
            if action.get("Insert"):
                s1 = hashlib.sha1()
                s1.update("+".join([ApplicationKey, ConsumerKey, "GET",
                                    "https://eu.api.ovh.com/1.0/cloud/project/%s/instance" % service, time]))
                sig = "$1$" + s1.hexdigest()
                queryHeaders = {"X-Ovh-Application": ApplicationKey, "X-Ovh-Timestamp": time,
                                "X-Ovh-Consumer": ConsumerKey, "X-Ovh-Signature": sig,
                                "Content-type": "application/json"}
                _body = '{"flavorId": %s,"imageId": "%s","monthlyBilling": false,"name": "%s","region": "%s"}' % (
                    FlavorId, ImageId, ServerName, Region)
                requests.post("https://eu.api.ovh.com/1.0/cloud/project/%s/instance" % service, headers=queryHeaders,
                              body=_body)
            elif action.get("Remove"):
                s1 = hashlib.sha1()
                s1.update("+".join([ApplicationKey, ConsumerKey, "GET",
                                    "https://eu.api.ovh.com/1.0/cloud/project/%s/instance" % service, time]))
                sig = "$1$" + s1.hexdigest()
                queryHeaders = {"X-Ovh-Application": ApplicationKey, "X-Ovh-Timestamp": time,
                                "X-Ovh-Consumer": ConsumerKey, "X-Ovh-Signature": sig,
                                "Content-type": "application/json"}
                requests.delete("https://eu.api.ovh.com/1.0/cloud/project/%s/instance/%s" % (service, ServerId),
                                headers=queryHeaders)
            elif action.get("Reboot"):
                s1 = hashlib.sha1()
                s1.update("+".join([ApplicationKey, ConsumerKey, "GET",
                                    "https://eu.api.ovh.com/1.0/cloud/project/%s/instance" % service, time]))
                sig = "$1$" + s1.hexdigest()
                queryHeaders = {"X-Ovh-Application": ApplicationKey, "X-Ovh-Timestamp": time,
                                "X-Ovh-Consumer": ConsumerKey, "X-Ovh-Signature": sig,
                                "Content-type": "application/json"}
                requests.post("https://eu.api.ovh.com/1.0/cloud/project/%s/instance/%s/reboot" % (service, ServerId),
                              headers=queryHeaders)
            elif action.get("Rebuild"):
                s1 = hashlib.sha1()
                s1.update("+".join([ApplicationKey, ConsumerKey, "GET",
                                    "https://eu.api.ovh.com/1.0/cloud/project/%s/instance" % service, time]))
                sig = "$1$" + s1.hexdigest()
                queryHeaders = {"X-Ovh-Application": ApplicationKey, "X-Ovh-Timestamp": time,
                                "X-Ovh-Consumer": ConsumerKey, "X-Ovh-Signature": sig,
                                "Content-type": "application/json"}
                requests.post("https://eu.api.ovh.com/1.0/cloud/project/%s/instance/%s/reinstall" % (service, ServerId),
                              headers=queryHeaders)
