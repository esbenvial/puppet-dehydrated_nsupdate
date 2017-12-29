class dehydrated_nsupdate (
  String $key_path              = '/etc/letsencrypt.sh/nsupdate_keys',
  Optional[String] $dns_server  = undef,
  Optional[String] $script_path = undef,
) {
  file { 'letsencrypt_acme_dns-01_challenge_hook.sh':
    ensure  => file,
    path    => "${script_path}/letsencrypt_acme_dns-01_challenge_hook.sh",
    content => epp("${module_name}/letsencrypt_acme_dns-01_challenge_hook.sh.epp"),
  }
}
