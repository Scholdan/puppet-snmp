# @summary
#   Creates a SNMPv3 user with authentication and encryption paswords.
#
# @example
#   snmp::snmpv3_user { 'myuser':
#     authtype => 'MD5',
#     authpass => '1234auth',
#     privpass => '5678priv',
#   }
#
# @param authpass
#   Authentication password for the user. May be a Sensitive value; the
#   password is kept out of catalogs, reports and logs either way.
#
# @param authtype
#   Authentication type for the user.  SHA or MD5
#
# @param privpass
#   Encryption password for the user. May be a Sensitive value; the
#   password is kept out of catalogs, reports and logs either way.
#
# @param privtype
#   Encryption type for the user.  AES or DES
#
# @param daemon
#   Which daemon file in which to write the user.  snmpd or snmptrapd
#
define snmp::snmpv3_user (
  Variant[String[8], Sensitive[String[8]]]           $authpass,
  Enum['SHA','MD5']                                  $authtype = 'SHA',
  Optional[Variant[String[8], Sensitive[String[8]]]] $privpass = undef,
  Enum['AES','DES']                                  $privtype = 'AES',
  Enum['snmpd','snmptrapd']                          $daemon   = 'snmpd'
) {
  include snmp

  $_authpass = $authpass ? { Sensitive => $authpass.unwrap, default => $authpass }
  $_privpass = $privpass ? { Sensitive => $privpass.unwrap, default => $privpass }

  if ($daemon == 'snmptrapd') and ($facts['os']['family'] != 'Debian') {
    $service_name   = 'snmptrapd'
  } else {
    $service_name   = 'snmpd'
  }

  $cmd = $_privpass ? {
    undef   => "createUser ${title} ${authtype} \"${_authpass}\"",
    default => "createUser ${title} ${authtype} \"${_authpass}\" ${privtype} \"${_privpass}\""
  }

  if ($title in $facts['snmpv3_user']) {
    # user details from config are available as fact
    $usm_user = $facts['snmpv3_user'][$title]

    $authhash = snmp::snmpv3_usm_hash($authtype, $usm_user['engine'], $_authpass)

    # privacy protocol key may be empty; truncate to 128 bits if used
    $privhash = empty($_privpass) ? {
      true    => '',
      default => snmp::snmpv3_usm_hash($authtype, $usm_user['engine'], $_privpass, 128)
    }

    # (re)create the user if at least one of the hashes is different
    $create = ($authhash != $usm_user['authhash']) or ($privhash != $usm_user['privhash'])
  }
  else {
    # user is unknown
    $create = true
  }

  if $create {
    unless defined(Exec["stop-${service_name}"]) {
      $command = $facts['service_provider'] ? {
        'systemd' => "systemctl stop ${service_name}; sleep 5",
        default   => "service ${service_name} stop ; sleep 5",
      }

      exec { "stop-${service_name}":
        command => $command,
        user    => 'root',
        cwd     => '/',
        path    => '/bin:/sbin:/usr/bin:/usr/sbin',
        require => File['var-net-snmp'],
      }
      if $snmp::manage_packages {
        Package['snmpd'] -> Exec["stop-${service_name}"]
      }
    }

    unless defined(File["${snmp::var_net_snmp}/${service_name}.conf"]) {
      #
      # For this file there is no content defined since the SNMP daemon
      # rewrites the content on exit. But the file needs to exist or the
      # following file_line resource will fail.
      #
      file { "${snmp::var_net_snmp}/${service_name}.conf":
        ensure => file,
        mode   => '0600',
        owner  => $snmp::varnetsnmp_owner,
        group  => $snmp::varnetsnmp_group,
      }
    }

    # The createUser line carries the plaintext passphrases: a file_line
    # would store them in the catalog (and PuppetDB). An exec with a
    # Sensitive command keeps them out of catalogs, reports and logs.
    # sed-then-append preserves the replace semantics file_line's match
    # provided.
    $conf_file = "${snmp::var_net_snmp}/${service_name}.conf"
    exec { "create-snmpv3-user-${title}":
      command  => Sensitive("sed -i '/^createUser ${title} /d' '${conf_file}' && echo ${stdlib::shell_escape($cmd)} >> '${conf_file}'"),
      provider => 'shell',
      require  => [Exec["stop-${service_name}"], File[$conf_file]],
      before   => Service[$service_name],
    }
  }

  # TODO: Add "rwuser ${title}" (or rouser) to /etc/snmp/${daemon}.conf
}
