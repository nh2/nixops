# -*- coding: utf-8 -*-
from __future__ import absolute_import

import os
import re
import socket
import struct
import subprocess32 as subprocess
import time

import hetznercloud
from hetznercloud import HetznerCloudClientConfiguration, HetznerCloudClient

from nixops import known_hosts
import nixops.util
from nixops.util import wait_for_tcp_port, ping_tcp_port
from nixops.util import attr_property, create_key_pair
from nixops.ssh_util import SSHCommandFailed
from nixops.backends import MachineDefinition, MachineState
from nixops.nix_expr import nix2py

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
            ["-o", "LogLevel=quiet",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "GlobalKnownHostsFile=/dev/null",
             "-o", "StrictHostKeyChecking=no"]
            if self.state == self.RESCUE else
            # XXX: Disabling strict host key checking will only impact the
            # behaviour on *new* keys, so it should be "reasonably" safe to do
            # this until we have a better way of managing host keys in
            # ssh_util. So far this at least avoids to accept every damn host
            # key on a large deployment.
            ["-o", "StrictHostKeyChecking=no"] + (["-i", file] if file else [])
        )

    def _wait_for_rescue(self, ip):
        # In test mode, the target machine really doesn't go down at all,
        # so only wait for the reboot to finish when deploying real
        # systems.
        self.log_start("waiting for rescue system...")
        dotlog = lambda: self.log_continue(".")  # NOQA
        wait_for_tcp_port(ip, 22, open=False, callback=dotlog)
        self.log_continue("[down]")
        wait_for_tcp_port(ip, 22, callback=dotlog)
        self.log_end("[up]")
        self.state = self.RESCUE

    def _bootstrap_rescue_for_existing_system(self):
        """
        Make sure that an existing system is easy to work on and set everything
        up properly to enter a chrooted shell on the target system.
        """
        self.log_start("mounting /mnt/run... ")
        self.run_command("mkdir -m 0755 -p /mnt/run")
        self.run_command("mount -t tmpfs -o mode=0755 none /mnt/run")
        self.log_end("done.")

        self.log_start("symlinking /mnt/run/current-system... ")
        self.run_command("ln -s /nix/var/nix/profiles/system "
                         "/mnt/run/current-system")
        self.log_end("done.")

        self.log_start("adding note on ‘nixos-enter’ to motd... ")
        cmd = "nixos-enter"
        msg = "Use {} to enter a shell on the target system"
        msglen = len(msg.format(cmd))
        csimsg = msg.format('\033[1;32m{}\033[37m'.format(cmd))
        hborder = "-" * (msglen + 2)
        fullmsg = '\033[1;30m{}\033[m\n\n'.format('\n'.join([
            "+{}+".format(hborder),
            "| \033[37;1m{}\033[30m |".format(csimsg),
            "+{}+".format(hborder),
        ]))
        self.run_command("cat >> /etc/motd", stdin_string=fullmsg)
        self.log_end("done.")

    def _bootstrap_rescue(self, install, partitions):
        """
        Bootstrap everything needed in order to get Nix and the partitioner
        usable in the rescue system. The keyword arguments are only for
        partitioning, see reboot_rescue() for description, if not given we will
        only mount based on information provided in self.partitions.
        """
        self.log_start("building Nix bootstrap installer... ")
        expr = os.path.join(self.depl.expr_path, "hetzner-bootstrap.nix")
        bootstrap_out = subprocess.check_output(["nix-build", expr,
                                                 "--no-out-link"]).rstrip()
        bootstrap = os.path.join(bootstrap_out, 'bin/hetzner-bootstrap')
        self.log_end("done. ({0})".format(bootstrap))

        self.log_start("creating nixbld group in rescue system... ")
        self.run_command("getent group nixbld > /dev/null || "
                         "groupadd -g 30000 nixbld")
        self.log_end("done.")

        self.log_start(
            "checking if tmpfs in rescue system is large enough... "
        )
        dfstat = self.run_command("stat -f -c '%a:%S' /", capture_stdout=True)
        df, bs = dfstat.split(':')
        free_mb = (int(df) * int(bs)) // 1024 // 1024
        if free_mb > 300:
            self.log_end("yes: {0} MB".format(free_mb))
            tarcmd = 'tar x -C /'
        else:
            self.log_end("no: {0} MB".format(free_mb))
            tarexcludes = ['*/include', '*/man', '*/info', '*/locale',
                           '*/locales', '*/share/doc', '*/share/aclocal',
                           '*/example', '*/terminfo', '*/pkgconfig',
                           '*/nix-support', '*/etc', '*/bash-completion',
                           '*.a', '*.la', '*.pc', '*.lisp', '*.pod', '*.html',
                           '*.pyc', '*.pyo', '*-kbd-*/share', '*-gcc-*/bin',
                           '*-gcc-*/libexec', '*-systemd-*/bin',
                           '*-boehm-gc-*/share']
            tarcmd = 'tar x -C / ' + ' '.join(["--exclude='{0}'".format(glob)
                                               for glob in tarexcludes])

        # The command to retrieve our split TAR archive on the other side.
        recv = 'read -d: tarsize; head -c "$tarsize" | {0}; {0}'.format(tarcmd)

        self.log_start("copying bootstrap files to rescue system... ")
        tarstream = subprocess.Popen([bootstrap], stdout=subprocess.PIPE)
        if not self.has_fast_connection:
            stream = subprocess.Popen(["gzip", "-c"], stdin=tarstream.stdout,
                                      stdout=subprocess.PIPE)
            self.run_command("gzip -d | ({0})".format(recv),
                             stdin=stream.stdout)
            stream.wait()
        else:
            self.run_command(recv, stdin=tarstream.stdout)
        tarstream.wait()
        self.log_end("done.")

        if install:
            # Workaround for https://github.com/NixOS/nixpart/issues/10
            self.log_start("disabling potentially active LVM arrays... ")
            self.run_command("vgchange -a n")

            self.log_start("partitioning disks... ")
            try:
                out = self.run_command("nixpart -p -", capture_stdout=True,
                                       stdin_string=partitions)
            except SSHCommandFailed as cmd:
                # Exit code 100 is when the partitioner requires a reboot.
                if cmd.exitcode == 100:
                    self.log(cmd.message)
                    self.reboot_rescue(install, partitions)
                    return
                else:
                    raise

            # This is the *only* place to set self.partitions unless we have
            # implemented a way to repartition the system!
            self.partitions = partitions
            self.fs_info = out
        else:
            self.log_start("mounting filesystems... ")
            self.run_command("nixpart -m -", stdin_string=self.partitions)
        self.log_end("done.")

        if not install:
            self.log_start("checking if system in /mnt is NixOS... ")
            res = self.run_command("test -e /mnt/etc/NIXOS", check=False)
            if res == 0:
                self.log_end("yes.")
                self._bootstrap_rescue_for_existing_system()
            else:
                self.log_end("NO! Not mounting special filesystems.")
                return

        self.log_start("bind-mounting special filesystems... ")
        for mountpoint in ("/proc", "/dev", "/dev/shm", "/sys"):
            self.log_continue("{0}...".format(mountpoint))
            cmd = "mkdir -m 0755 -p /mnt{0} && ".format(mountpoint)
            cmd += "mount --bind {0} /mnt{0}".format(mountpoint)
            self.run_command(cmd)
        self.log_end("done.")

    def reboot(self, hard=False, reset=True):
        self.log("rebooting HetznerCloud server...")
        server = self._get_server(self.get_api_token_from_env_or_state())
        action = server.reset()
        action.wait_until_status_is(ACTION_STATUS_SUCCESS)
        self.state = self.STARTING

    def reboot_rescue(self, install=False, partitions=None, bootstrap=True,
                      hard=False):
        """
        Use the Robot to activate the rescue system and reboot the system. By
        default, only mount partitions and do not partition or wipe anything.

        On installation, both 'installed' has to be set to True and partitions
        should contain a Kickstart configuration, otherwise it's read from
        self.partitions if available (which it shouldn't if you're not doing
        something nasty).
        """
        self.log("rebooting machine ‘{0}’ ({1}) into rescue system"
                 .format(self.name, self.main_ipv4))
        server = self._get_server_by_ip(self.main_ipv4)
        server.rescue.activate()
        rescue_passwd = server.rescue.password
        if hard or (install and self.state not in (self.UP, self.RESCUE)):
            self.log_start("sending hard reset to robot... ")
            server.reboot('hard')
        else:
            self.log_start("sending reboot command... ")
            if self.state == self.RESCUE:
                self.run_command("(sleep 2; reboot) &", check=False)
            else:
                self.run_command("systemctl reboot", check=False)
        self.log_end("done.")
        self._wait_for_rescue(self.main_ipv4)
        self.rescue_passwd = rescue_passwd
        self.state = self.RESCUE
        self.ssh.reset()
        if bootstrap:
            self._bootstrap_rescue(install, partitions)

    def _install_base_system(self):
        self.log_start("creating missing directories... ")
        cmds = ["mkdir -m 1777 -p /mnt/tmp /mnt/nix/store"]
        mntdirs = ["var", "etc", "bin", "nix/var/nix/gcroots",
                   "nix/var/nix/temproots", "nix/var/nix/manifests",
                   "nix/var/nix/userpool", "nix/var/nix/profiles",
                   "nix/var/nix/db", "nix/var/log/nix/drvs"]
        to_create = ' '.join(map(lambda d: os.path.join("/mnt", d), mntdirs))
        cmds.append("mkdir -m 0755 -p {0}".format(to_create))
        self.run_command(' && '.join(cmds))
        self.log_end("done.")

        self.log_start("bind-mounting files in /etc... ")
        for etcfile in ("resolv.conf", "passwd", "group"):
            self.log_continue("{0}...".format(etcfile))
            cmd = ("if ! test -e /mnt/etc/{0}; then"
                   " touch /mnt/etc/{0} && mount --bind /etc/{0} /mnt/etc/{0};"
                   " fi").format(etcfile)
            self.run_command(cmd)
        self.log_end("done.")

        self.log("setting custom nix.conf options in chroot")
        self.run_command("mkdir -p /mnt/etc/nix && echo 'binary-caches = http://nixos-cache.benaco.com/ http://cache.nixos.org\nbuild-max-jobs = 5' > /mnt/etc/nix/nix.conf")

        self.run_command("touch /mnt/etc/NIXOS")
        self.run_command("activate-remote")

        self.main_ssh_private_key, self.main_ssh_public_key = create_key_pair(
            key_name="NixOps client key of {0}".format(self.name)
        )
        self._gen_network_spec()

    def _detect_hardware(self):
        self.log_start("detecting hardware... ")
        cmd = "nixos-generate-config --no-filesystems --show-hardware-config"
        hardware = self.run_command(cmd, capture_stdout=True)
        self.hw_info = '\n'.join([line for line in hardware.splitlines()
                                  if not line.lstrip().startswith('#')])
        self.log_end("done.")

    def switch_to_configuration(self, method, sync, command=None):
        if self.state == self.RESCUE:
            # We cannot use the mountpoint command here, because it's unable to
            # detect bind mounts on files, so we just go ahead and try to
            # unmount.
            umount = 'if umount "{0}" 2> /dev/null; then rm -f "{0}"; fi'
            cmd = '; '.join([umount.format(os.path.join("/mnt/etc", mnt))
                             for mnt in ("resolv.conf", "passwd", "group")])
            self.run_command(cmd)

            command = "chroot /mnt /nix/var/nix/profiles/system/bin/"
            command += "switch-to-configuration"

        res = MachineState.switch_to_configuration(self, method, sync, command)
        if res not in (0, 100):
            return res
        if self.state == self.RESCUE and self.just_installed:
            self.reboot_sync()
            self.just_installed = False
        return res

    def _get_ethernet_interfaces(self):
        """
        Return a list of all the ethernet interfaces active on the machine.
        """
        # We don't use \(\) here to ensure this works even without GNU sed.
        cmd = "ip addr show | sed -n -e 's/^[0-9]*: *//p' | cut -d: -f1"
        return self.run_command(cmd, capture_stdout=True).splitlines()

    def _get_mac_address_for_interface(self, interface):
        cmd = "cat /sys/class/net/" + interface + "/address"
        mac_addr = self.run_command(cmd, capture_stdout=True).strip()
        # Regex from https://stackoverflow.com/a/4260512/263061
        assert re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac_addr), "unexpected MAC address"
        return mac_addr

    def _get_udev_rule_for(self, interface):
        """
        Get lines suitable for services.udev.extraRules for 'interface',
        and thus essentially map the device name to a hardware address.
        """
        cmd = "ip addr show \"{0}\" | sed -n -e 's|^.*link/ether  *||p'"
        cmd += " | cut -d' ' -f1"
        mac_addr = self.run_command(cmd.format(interface),
                                    capture_stdout=True).strip()

        rule = 'ACTION=="add", SUBSYSTEM=="net", ATTR{{address}}=="{0}", '
        rule += 'NAME="{1}"'
        return rule.format(mac_addr, interface)

    def _get_ipv4_addr_and_prefix_for(self, interface):
        """
        Return a tuple of (ipv4_address, prefix_length) for the specified
        interface.
        """
        cmd = "ip addr show \"{0}\" | sed -n -e 's/^.*inet  *//p'"
        cmd += " | cut -d' ' -f1"
        ipv4_addr_prefix = self.run_command(cmd.format(interface),
                                            capture_stdout=True).strip()
        if "/" not in ipv4_addr_prefix:
            # No IP address set for this interface.
            return None
        else:
            return ipv4_addr_prefix.split('/', 1)

    def _get_default_gw(self):
        """
        Return the default gateway of the currently running machine.
        """
        cmd = "ip route list | sed -n -e 's/^default  *via  *//p'"
        cmd += " | cut -d' ' -f1"
        return self.run_command(cmd, capture_stdout=True).strip()

    def _get_nameservers(self):
        """
        Return a list of all nameservers defined on the currently running
        machine.
        """
        cmd = "cat /etc/resolv.conf | sed -n -e 's/^nameserver  *//p'"
        return self.run_command(cmd, capture_stdout=True).splitlines()

    def _indent(self, lines, level=1):
        """
        Indent list of lines by the specified level (one level = two spaces).
        """
        return map(lambda line: "  " + line, lines)

    def _calculate_ipv4_subnet(self, ipv4, prefix_len):
        """
        Returns the address of the subnet for the given 'ipv4' and
        'prefix_len'.
        """
        bits = struct.unpack('!L', socket.inet_aton(ipv4))[0]
        mask = 0xffffffff >> (32 - prefix_len) << (32 - prefix_len)
        return socket.inet_ntoa(struct.pack('!L', bits & mask))

    def _gen_network_spec(self, server):
        """
        Generate Nix expressions related to networking configuration based on
        the currently running machine (most likely in RESCUE state) and set the
        resulting string to self.net_info.
        """
        udev_rules = []
        iface_attrs = {}
        extra_routes = []
        ipv6_commands = []

        # Global networking options
        defgw = self._get_default_gw()
        v6defgw = None

        # Interface-specific networking options
        for iface in self._get_ethernet_interfaces():
            if iface == "lo":
                continue

            result = self._get_ipv4_addr_and_prefix_for(iface)
            if result is None:
                continue

            udev_rules.append(self._get_udev_rule_for(iface))

            ipv4, prefix = result
            iface_attrs[iface] = {
                'ipAddress': ipv4,
                'prefixLength': int(prefix),
            }

            # Extra route for accessing own subnet
            net = self._calculate_ipv4_subnet(ipv4, int(prefix))
            extra_routes.append(("{0}/{1}".format(net, prefix), defgw, iface))

            # # IPv6 subnets only for eth0 (XXX: more flexibility here?)
            # v6addr_command = "ip -6 addr add '{0}' dev '{1}' || true"
            # for subnet in server.subnets:
            #     if "." in subnet.net_ip:
            #         # skip IPv4 addresses
            #         continue
            #     v6addr = "{0}/{1}".format(subnet.net_ip, subnet.mask)
            #     ipv6_commands.append(v6addr_command.format(v6addr, iface))
            #     assert v6defgw is None or v6defgw == subnet.gateway
            #     v6defgw = subnet.gateway

        # Extra routes
        route4_cmd = "ip -4 route change '{0}' via '{1}' dev '{2}' || true"
        route_commands = [route4_cmd.format(network, gw, iface)
                          for network, gw, iface in extra_routes]

        # IPv6 configuration
        route6_cmd = "ip -6 route add default via '{0}' dev eth0 || true"
        route_commands.append(route6_cmd.format(v6defgw))

        local_commands = '\n'.join(ipv6_commands + route_commands) + '\n'

        self.net_info = {
        }

    def get_physical_spec(self):
        # def prefix_len(netmask):
        #     return bin(int(socket.inet_aton(netmask).encode('hex'), 16)).count('1')
        # networking = {
        #     ('interfaces', 'enp0s3', 'ip4'): [{"address": self.public_ipv4, 'prefixLength': prefix_len(self.netmask)}],
        # }
        # return Function("{ ... }", {
        #     'imports': [ RawValue('<nixpkgs/nixos/modules/profiles/qemu-guest.nix>') ],
        #     'networking': networking,
        #     # TODO check if this stuff is needed
        #     ('boot', 'initrd', 'availableKernelModules') = ["ata_piix", "uhci_hcd", "virtio_pci"];
        #     # ('users', 'extraUsers', 'root', 'openssh', 'authorizedKeys', 'keys'): [self.depl.active_resources.get('ssh-key').public_key],
        # })

        # if all([self.net_info, self.fs_info, self.hw_info,
        # if all([self.net_info,                 self.hw_info,
        #         self.main_ssh_public_key]):
        return {
            'config': {
                'services': {
                    # 'udev': {'extraRules': '\n'.join(udev_rules) + '\n'},
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

        if self.state not in (self.RESCUE, self.UP) or check:
            self.check()

        self.set_common_state(defn)

        # Check whether the server hasn't been killed behind our
        # backs.  Restart stopped instances.
        if self.vm_id and check:
            server = self._get_server(self.get_api_token_from_env_or_defn(defn))

            # TODO implement this as ec2.py does

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
                    server.wait_until_status_is(hetznercloud.SERVER_STATUS_INITIALIZING, attempts=100, wait_seconds=0)
                    break
                except hetznercloud.HetznerWaitAttemptsExceededException as e:
                    self.log_continue(".")
                    time.sleep(1)
                except hetznercloud.HetznerRateLimitExceeded as e:
                    self.log_continue("[rate limit exceeded]")
                    time.sleep(1)
            self.log_end("done.")

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
                self.vm_id = server.id
                self.image = defn.image
                self.server_type = defn.server_type
                self.ssh_keys = defn.ssh_keys
                self.private_host_key = None
                # From the reply
                self.public_ipv4 = server.public_net_ipv4

            self._detect_hardware()
            self.main_ssh_private_key, self.main_ssh_public_key = create_key_pair(
                key_name="NixOps client key of {0}".format(self.name)
            )
            # self._gen_network_spec(server)

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
            self.mac_address = self._get_mac_address_for_interface(initial_interface_name)
            self.interface_name = initial_interface_name

        # if not self.vm_id:
        #     self.log("installing machine...")
        #     self.reboot_rescue(install=True, partitions=defn.partitions)
        #     self._install_base_system()
        #     self._detect_hardware()
        #     server = self._get_server_by_ip(self.main_ipv4)
        #     vm_id = "nixops-{0}-{1}".format(self.depl.uuid, self.name)
        #     server.set_name(vm_id[:100])
        #     self.vm_id = vm_id
        #     known_hosts.remove(self.main_ipv4, None)
        #     self.just_installed = True
        #     self.state_version = defn.config['nixosRelease']

    def start(self):
        """
        Start the server into the normal system (a reboot is done if the rescue
        system is active).
        """
        if self.state == self.UP:
            return
        elif self.state == self.RESCUE:
            self.reboot()
        elif self.state in (self.STOPPED, self.UNREACHABLE):
            self.log_start("server was shut down, sending hard reset... ")
            server = self._get_server_by_ip(self.main_ipv4)
            server.reboot("hard")
            self.log_end("done.")
            self.state = self.STARTING
        self.wait_for_ssh(check=True)
        self.send_keys()

    def _wait_stop(self):
        """
        Wait for the system to shutdown and set state STOPPED afterwards.
        """
        self.log_start("waiting for system to shutdown... ")
        dotlog = lambda: self.log_continue(".")  # NOQA
        wait_for_tcp_port(self.main_ipv4, 22, open=False, callback=dotlog)
        self.log_continue("[down]")

        self.state = self.STOPPED

    def stop(self):
        """
        Stops the server by shutting it down without powering it off.
        """
        if self.state not in (self.RESCUE, self.UP):
            return
        self.log_start("shutting down system... ")
        self.run_command("systemctl halt", check=False)
        self.log_end("done.")

        self.state = self.STOPPING
        self._wait_stop()

    def get_ssh_name(self):
        assert self.public_ipv4
        return self.public_ipv4

    def get_ssh_password(self):
        if self.state == self.RESCUE:
            return self.rescue_passwd
        else:
            return None

    def _check(self, res):
        if not self.vm_id:
            res.exists = False
            return

        if self.state in (self.STOPPED, self.STOPPING):
            res.is_up = ping_tcp_port(self.main_ipv4, 22)
            if not res.is_up:
                self.state = self.STOPPED
                res.is_reachable = False
                return

        res.exists = True
        avg = self.get_load_avg()
        if avg is None:
            if self.state in (self.UP, self.RESCUE):
                self.state = self.UNREACHABLE
            res.is_reachable = False
            res.is_up = False
        elif self.run_command("test -f /etc/NIXOS", check=False) != 0:
            self.state = self.RESCUE
            self.ssh_pinged = True
            self._ssh_pinged_this_time = True
            res.is_reachable = True
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
