# Configuration specific to the Hetzner backend.

{ config, lib, ... }:

with lib;

{
  ###### interface

  options.deployment.hetznercloud = {
    apiToken = mkOption {
      example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      type = types.str;
      description = ''
        The Hetzner API token credential.
      '';
    };

    serverName = mkOption {
      example = "my-server";
      type = types.str;
      description = ''
        Name of the server to create (must be unique per Hetzner Cloud project
        and a valid hostname as per RFC 1123).
      '';
    };

    serverType = mkOption {
      default = null;
      example = "cx21";
      type = types.nullOr types.str;
      description = ''
        ID or name of the server type this server should be created with.
        See <link xlink:href='https://www.hetzner.de/cloud#pricing'/> for a
        list of valid server types.
      '';
    };

    image = mkOption {
      example = "my-custom-image-name";
      type = types.str;
      description = ''
        ID or name of the image the server is created from.
        Should be a NixOS image for NixOps to work.
        Currently you have to create this manually using a snapshot;
        NixOps cannot yet create a NixOS image on HetznerCloud for you.
      '';
    };

    location = mkOption {
      default = null;
      example = "fsn1";
      type = types.nullOr types.str;
      description = ''
        ID or name of location to create server in.

        Can be left as `null` to let Hetzner choose.

        Will be ignored if the more specific option `datacenter` is set.

        As of writing, the available data centers are
        nbg1, fsn1, hel1.

        See <link xlink:href='https://docs.hetzner.cloud/#resources-locations'/>
        for an API call to list of all data center names.
      '';
    };

    datacenter = mkOption {
      default = null;
      example = "fsn1-dc8";
      type = types.nullOr types.str;
      description = ''
        ID or name of datacenter to create server in.

        Can be left as `null` to let Hetzner choose.

        This is even more specific than setting a location.

        Note as per Hetzner, directly specifying the datacenter is discouraged
        since supply availability in datacenters varies greatly and datacenters
        may be out of stock for extended periods of time or not serve certain
        server types at all.

        See <link xlink:href='https://docs.hetzner.cloud/#resources-datacenters'/>
        for an API call to list of all data center names.
      '';
    };

    sshKeys = mkOption {
      default = [];
      example = [ "key for user1" "key for user2" ];
      type = types.listOf types.str;
      description = ''
        Names of SSH keys to assign to the server.
        The SSH keys must have be created manually in the Hetzner
        Cloud UI first.
      '';
    };

    # TODO Possible to add `instanceId` like for EC2?


    partitions = mkOption {
      default = ''
        clearpart --all --initlabel --drives=sda,sdb

        part swap1 --recommended --label=swap1 --fstype=swap --ondisk=sda
        part swap2 --recommended --label=swap2 --fstype=swap --ondisk=sdb

        part raid.1 --grow --ondisk=sda
        part raid.2 --grow --ondisk=sdb

        raid / --level=1 --device=md0 --fstype=ext4 --label=root raid.1 raid.2
      '';
      example = ''
        # Example for partitioning on a vServer:
        clearpart --all --initlabel --drives=vda
        part swap --recommended --label=swap --fstype=swap --ondisk=vda
        part / --fstype=ext4 --label=root --grow --ondisk=vda
      '';
      type = types.lines;
      description = ''
        Specify layout of partitions and file systems using Anacondas Kickstart
        format. For possible options and commands, please have a look at:

        <link xlink:href="http://fedoraproject.org/wiki/Anaconda/Kickstart"/>
      '';
    };
  };

  ###### implementation

  config = mkIf (config.deployment.targetEnv == "hetznercloud") {
    nixpkgs.system = mkOverride 900 "x86_64-linux";
    boot.loader.grub.version = 2;
    boot.loader.timeout = 1;
    services.openssh.enable = true;

    security.initialRootPassword = mkDefault "!";
  };
}
