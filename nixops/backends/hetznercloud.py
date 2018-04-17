# -*- coding: utf-8 -*-
from __future__ import absolute_import

import os
import re
import time

import hetznercloud
from hetznercloud import HetznerCloudClientConfiguration, HetznerCloudClient

import nixops.util
from nixops.util import wait_for_tcp_port, ping_tcp_port
from nixops.util import attr_property, create_key_pair
from nixops.backends import MachineDefinition, MachineState
from nixops.nix_expr import nix2py

# TODO Not all `hetznercloud` API calls in this module retry `HetznerRateLimitExceeded` yet. They should.

def network_interface_name_for_nixos_version(nixos_version_string):
    # See https://github.com/NixOS/nixpkgs/commit/49d34a49650182129ce1c5d0a453ae9823c4ff06
    assert len(nixos_version_string) > 0
    return "ens3" if nixops.util.parse_nixos_version(nixos_version_string) >= ["17", "09"] else "enp0s3"

class HetznerCloudDefinition(MachineDefinition):
    """
    Definition of a HetznerCloud machine.
    """
    @classmethod
    def get_type(cls):
        return "hetznercloud"

    def __init__(self, xml, config):
        MachineDefinition.__init__(self, xml, config)

        self.api_token = config["hetznercloud"]["apiToken"]
        self.server_name = config["hetznercloud"]["serverName"]
        self.server_type = config["hetznercloud"]["serverType"]
        self.image = config["hetznercloud"]["image"]
        self.location = config["hetznercloud"]["location"]
        self.datacenter = config["hetznercloud"]["datacenter"]
        self.ssh_keys = config["hetznercloud"]["sshKeys"]

    def host_key_type(self):
        return "ed25519" if nixops.util.parse_nixos_version(self.config["nixosRelease"]) >= ["15", "09"] else "dsa"

    def network_interface_name(self):
        return network_interface_name_for_nixos_version(self.config["nixosRelease"])

class HetznerCloudState(MachineState):
    """
    State of a HetznerCloud machine.
    """
    @classmethod
    def get_type(cls):
        return "hetznercloud"

    state = attr_property("state", MachineState.MISSING, int)  # override

    public_ipv4 = attr_property("publicIpv4", None)
    api_token = attr_property("hetznercloud.apiToken", None)
    server_name = attr_property("hetznercloud.serverName", None)
    server_type = attr_property("hetznercloud.serverType", None)
    image = attr_property("hetznercloud.image", None)
    location = attr_property("hetznercloud.location", None)
    datacenter = attr_property("hetznercloud.datacenter", None)
    ssh_keys = attr_property("hetznercloud.sshKeys", {}, 'json')

    main_ssh_private_key = attr_property("hetznercloud.sshPrivateKey", None)
    main_ssh_public_key = attr_property("hetznercloud.sshPublicKey", None)
    public_host_key = attr_property("hetznercloud.publicHostKey", None)
    private_host_key = attr_property("hetznercloud.privateHostKey", None)
    mac_address = attr_property("hetzner.macAddress", None)
    interface_name = attr_property("hetzner.interfaceName", None)

    def __init__(self, depl, name, id):
        MachineState.__init__(self, depl, name, id)

    @property
    def resource_id(self):
        return self.vm_id

    # Note: Getting the auth token from the machine definition is always
    # better (more up-to-date) than getting it from the state, but not
    # all functions have access to the definition.
    # See https://github.com/NixOS/nixops/issues/627.
    def get_api_token_from_env_or_defn(self, defn):
        api_token = os.environ.get('HETZNERCLOUD_API_TOKEN', defn.api_token)

        if api_token is None:
            raise Exception("please either set ‘deployment.hetznercloud.apiToken’"
                            " or $HETZNERCLOUD_API_TOKEN for machine"
                            " ‘{0}’".format(self.name))

        return api_token

    def get_api_token_from_env_or_state(self):
        token = os.environ.get('HETZNERCLOUD_API_TOKEN', self.api_token)
        assert token, "auth_token not found in state, set it with the HETZNERCLOUD_API_TOKEN env var or set ‘deployment.hetznercloud.apiToken’ and redeploy"
        return token

    def get_client(self, api_token):
        configuration = HetznerCloudClientConfiguration().with_api_key(api_token).with_api_version(1)
        # As of writing, a `HetznerCloudClient` just contains its configuration,
        # and does not keep an open connection, so we don't try cache it.
        return HetznerCloudClient(configuration)

    def _get_server(self, api_token):
        """Get server object for this machine, with caching"""
        assert self.vm_id

        # Hetzner Server IDs are always integers; crash here if not
        vm_id_int = int(self.vm_id)

        return self.get_client(api_token).servers().get(vm_id_int)

    def get_ssh_private_key_file(self):
        if self._ssh_private_key_file:
            return self._ssh_private_key_file
        else:
            return self.write_ssh_private_key(self.main_ssh_private_key)

    def get_ssh_flags(self, *args, **kwargs):
        # TODO Put the SSH host key on the machine during creation,
        #      like we do for EC2, so that we don't have to disable
        #      StrictHostKeyChecking.
        #file = self.get_ssh_private_key_file()
        file = None
        return super(HetznerCloudState, self).get_ssh_flags(*args, **kwargs) + (
            # XXX: Disabling strict host key checking will only impact the
            # behaviour on *new* keys, so it should be "reasonably" safe to do
            # this until we have a better way of managing host keys in
            # ssh_util. So far this at least avoids to accept every damn host
            # key on a large deployment.
            ["-o", "StrictHostKeyChecking=no"] + (["-i", file] if file else [])
        )

    def reboot(self, hard=False, reset=True):
        if hard:
            self.log_start("hard-resetting HetznerCloud server...")

            server = self._get_server(self.get_api_token_from_env_or_state())
            _action = server.reset()

            self.state = self.STARTING
            if reset:
                self.ssh.reset()

            while True:
                try:
                    server.wait_until_status_is(hetznercloud.SERVER_STATUS_RUNNING, attempts=1, wait_seconds=0)
                    break
                except hetznercloud.HetznerWaitAttemptsExceededException as e:
                    self.log_continue(".")
                    time.sleep(1)
                except hetznercloud.HetznerRateLimitExceeded as e:
                    self.log_continue("[rate limit exceeded]")
                    time.sleep(1)

            self.log_end("done")
        else:
            return super(HetznerCloudState, self).reboot(hard=hard, reset=reset)

    def reboot_rescue(self, hard=False):
        # TODO implement
        self.warn("booting hetznercloud machine ‘{0}’ into rescue mode is possible"
                  " but is not yet implemented in nixops.".format(self.name))

    def _get_mac_address_for_interface(self, interface):
        cmd = "cat /sys/class/net/" + interface + "/address"
        mac_addr = self.run_command(cmd, capture_stdout=True).strip()
        # Regex from https://stackoverflow.com/a/4260512/263061
        assert re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac_addr), "unexpected MAC address"
        return mac_addr

    def get_physical_spec(self):
        return {
            'config': {
                'services': {
                    # See note [Network interface renaming]
                    'udev': {'extraRules': 'ACTION=="add", SUBSYSTEM=="net", ATTR{address}=="' + self.mac_address + '", NAME="' + self.interface_name + '"\n'},
                },
                'networking': {
                    # For the interface naming, see
                    #   https://github.com/NixOS/nixpkgs/commit/49d34a49650182129ce1c5d0a453ae9823c4ff06
                    ('interfaces', self.interface_name): {
                      'ipAddress': self.public_ipv4,
                      'prefixLength': 32,
                    },

                    # Hetzner cloud needs these static routes, see
                    # https://wiki.hetzner.de/index.php/VServer/en#Which_network_configuration_must_be_done.3F
                    ('dhcpcd', 'enable'): False,
                    'localCommands': '\n'.join([
                        "ip route add 172.31.1.1 dev " + self.interface_name,
                        "ip route add default via 172.31.1.1",
                    ]),

                    # See https://wiki.hetzner.de/index.php/Hetzner_Standard_Name_Server/en
                    'nameservers': [
                        "213.133.98.98",
                        "213.133.99.99",
                        "213.133.100.100",
                    ],
                },
                ('users', 'extraUsers', 'root', 'openssh', 'authorizedKeys', 'keys'): [self.main_ssh_public_key],
                ('boot', 'loader', 'grub', 'device'): '/dev/sda',
                ('fileSystems', '/'): { 'device': '/dev/sda1', 'fsType': 'ext4' },
            },
            # Without the modules below, the VM cannot see the disk (/dev/sda).
            'imports': [nix2py('''
                {
                  imports =
                    [ <nixpkgs/nixos/modules/profiles/qemu-guest.nix>
                    ];

                  boot.initrd.availableKernelModules = [ "ata_piix" "uhci_hcd" "virtio_pci" "sd_mod" "sr_mod" ];
                  boot.kernelModules = [ ];
                  boot.extraModulePackages = [ ];
                }
            ''')],
        }

    def create(self, defn, check, allow_reboot, allow_recreate):
        assert isinstance(defn, HetznerCloudDefinition)

        if self.state not in (self.UP,) or check:
            self.check()

        self.set_common_state(defn)

        # Check whether the server hasn't been killed behind our
        # backs.  Restart stopped instances.
        if self.vm_id and check:
            server = self._get_server(self.get_api_token_from_env_or_defn(defn))

            # TODO implement this as ec2.py does

        # TODO: Handle server resize, consider `allow_reboot` for that

        # Create the instance.
        if not self.vm_id:

            # Generate a public/private host key.
            if not self.public_host_key:
                (private, public) = nixops.util.create_key_pair(type=defn.host_key_type())
                with self.depl._db:
                    self.public_host_key = public
                    self.private_host_key = private

            user_data = "SSH_HOST_{2}_KEY_PUB:{0}\nSSH_HOST_{2}_KEY:{1}\n".format(
                self.public_host_key, self.private_host_key.replace("\n", "|"),
                defn.host_key_type().upper())

            token = self.get_api_token_from_env_or_defn(defn)
            self.api_token = token

            self.log_start("creating HetznerCloud server (image ‘{0}’, type ‘{1}’, location/datacenter ‘{2}’, name ‘{3}’)...".format(
                defn.image, defn.server_type, defn.datacenter or defn.location, defn.server_name))

            server, _create_action = self.get_client(token).servers().create(
                name=defn.server_name,
                server_type=defn.server_type,
                image=defn.image,
                # Only one of location or datacenter will be non-None;
                # if datacenter (more specific) is set, location is set to None.
                location=defn.location if defn.datacenter is None else None,
                datacenter=defn.datacenter,
                start_after_create=True,
                ssh_keys=defn.ssh_keys,
                user_data=user_data,
                )
            self.log_end("done.")

            self.log_start("waiting for server to be initializing...")
            while True:
                try:
                    server.wait_until_status_is(hetznercloud.SERVER_STATUS_INITIALIZING, attempts=1, wait_seconds=0)
                    break
                except hetznercloud.HetznerWaitAttemptsExceededException as e:
                    self.log_continue(".")
                    time.sleep(1)
                except hetznercloud.HetznerRateLimitExceeded as e:
                    self.log_continue("[rate limit exceeded]")
                    time.sleep(1)
            self.log_end("done.")

            self.state = self.STARTING

            self.log_start("waiting for server to be running...")
            while True:
                try:
                    server.wait_until_status_is(hetznercloud.SERVER_STATUS_RUNNING, attempts=1, wait_seconds=0)
                    break
                except hetznercloud.HetznerWaitAttemptsExceededException as e:
                    self.log_continue(".")
                    time.sleep(1)
                except hetznercloud.HetznerRateLimitExceeded as e:
                    self.log_continue("[rate limit exceeded]")
                    time.sleep(1)
            self.log_end("done.")

            with self.depl._db:
                self.image = defn.image
                self.server_type = defn.server_type
                self.ssh_keys = defn.ssh_keys
                self.private_host_key = None
                # From the reply
                self.vm_id = server.id
                self.public_ipv4 = server.public_net_ipv4

            self.main_ssh_private_key, self.main_ssh_public_key = create_key_pair(
                key_name="NixOps client key of {0}".format(self.name)
            )

            # Note [Network interface renaming]
            #
            # The funny Linux/systemd network interface renaming as described in
            #   https://github.com/NixOS/nixpkgs/commit/49d34a49650182129ce1c5d0a453ae9823c4ff06
            # poses a risk for servers: When upgrading from e.g. NixOS 17.03 to 17.09,
            # after the reboot the default network interface comes back as 'ens3' when
            # before it was `enp0s3`.
            # Obviously that's bad for NixOps:
            # The default image at the cloud provider with which a newly created server
            # boots before NixOps starts modifying it might be e.g. 17.03, and the version
            # the user wants to deploy might be 17.09.
            # When nixops wants to initially deploy the booted machine, it has to mention
            # the interface name in the config. The dilemma:
            # * If it uses 'enp0s3', then after a reboot that interface will not exist.
            # * If it uses 'ens3', then the `nixos-rebuild switch` part of the
            #   deploy will fail because that interface doesn't exist on the running system.
            # The release notes in
            #   https://github.com/NixOS/nixpkgs/commit/49d34a49650182129ce1c5d0a453ae9823c4ff06#diff-ca92d8c04b70cab44f3b2d91f0dbd9c1R220
            # mention:
            #   After changing the interface names, rebuild your system with
            #   `nixos-rebuild boot` [instead of `switch`] to activate the new
            #   configuration after a reboot. If you switch to the new
            #   configuration right away you might lose network connectivity!
            # However, nixops can't do that, it always uses `switch`.
            #
            # As a workaround, we add a udev rule to the physical spec that fixes
            # the interface name for that MAC address to whatever it was in the
            # NixOS image booted from the cloud provider.
            # We cannot fix it to the interface name that would be chosen by
            # the NixOS configuration deployed by the user through NixOps,
            # because that would require an interface name change while it
            # is in use, which Linux bails on with "Device or resource busy".
            # As a result, the `hetznercloud.image` setting will determine the
            # interface name, from the creation of the VM forever into the future,
            # independent of NixOS/systemd udpates.

            # Determine pre-deploy NixOS version
            image_os_release = self.run_command("cat /etc/os-release", capture_stdout=True)
            match = re.search('VERSION_ID="([0-9]+\.[0-9]+).*"', image_os_release)
            assert match, "Cannot determine version from the booted NixOS image"
            image_nixos_version = match.group(1)

            # Determine mac address and set target interface name
            initial_interface_name = network_interface_name_for_nixos_version(image_nixos_version)
            mac_address = self._get_mac_address_for_interface(initial_interface_name)
            with self.depl._db:
                self.mac_address = mac_address
                self.interface_name = initial_interface_name

    def start(self):
        if self.state == self.UP:
            return
        elif self.state == self.UNREACHABLE:
            self.log("server is unreachable, will hard reboot")
            self.reboot(hard=True)
        elif self.state == self.STOPPED:
            self.log_start("server stopped, sending boot request... ")

            server = self._get_server(self.get_api_token_from_env_or_state())
            action = server.power_on()
            self.state = self.STARTING
            while True:
                try:
                    action.wait_until_status_is(hetznercloud.ACTION_STATUS_SUCCESS, attempts=1, wait_seconds=0)
                    break
                except hetznercloud.HetznerWaitAttemptsExceededException as e:
                    self.log_continue(".")
                    time.sleep(1)
                except hetznercloud.HetznerRateLimitExceeded as e:
                    self.log_continue("[rate limit exceeded]")
                    time.sleep(1)

            self.log_end("done.")

        self.wait_for_ssh(check=True)
        self.send_keys()

    def stop(self):
        """
        Stops the server by shutting it down without powering it off.
        """
        # TODO Possibly use the API's `shutdown()` function instead
        print self.show_state()
        if self.state not in (self.UP,):
            return
        self.log_start("shutting down system... ")
        self.run_command("systemctl poweroff", check=False)
        self.log_end("done.")

        self.state = self.STOPPING

        # TODO: Replace this by a loop to the API that checks whether the server is actually off
        self.log_start("waiting for system to shutdown... ")
        dotlog = lambda: self.log_continue(".")  # NOQA
        wait_for_tcp_port(self.public_ipv4, 22, open=False, callback=dotlog)
        self.log_continue("[down]")

        self.state = self.STOPPED

    def get_ssh_name(self):
        assert self.public_ipv4
        return self.public_ipv4

    def _check(self, res):
        if not self.vm_id:
            res.exists = False
            return

        if self.state in (self.STOPPED, self.STOPPING):
            res.is_up = ping_tcp_port(self.public_ipv4, 22)
            if not res.is_up:
                self.state = self.STOPPED
                res.is_reachable = False
                return

        res.exists = True
        avg = self.get_load_avg()
        if avg is None:
            if self.state in (self.UP,):
                self.state = self.UNREACHABLE
            res.is_reachable = False
            res.is_up = False
        else:
            res.is_up = True
            MachineState._check(self, res)

    def destroy(self, wipe=False):
        if wipe:
            self.depl.logger.warn("wipe is not supported for the hetznercloud backend")

        # Create the instance as early as possible so if we don't have the
        # needed credentials, we can avoid to ask for confirmation.
        server = self._get_server(self.get_api_token_from_env_or_state())

        question = "are you sure you want to destroy HetznerCloud machine ‘{0}’".format(self.name)
        if not self.depl.logger.confirm(question):
            return False

        self.log("destroying HetznerCloud server (ID ‘{0}’, name ‘{1}’)...".format(
            self.vm_id, self.server_name))

        try:
            action = server.delete()
            action.wait_until_status_is(hetznercloud.ACTION_STATUS_SUCCESS)
        except hetznercloud.HetznerServerNotFoundException:
            self.warn("seems to have been destroyed already")

        # TODO remove from known hosts once implemented

        self.vm_id = None
        self.state = self.STOPPED

        return True
