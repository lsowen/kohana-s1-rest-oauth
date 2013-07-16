<?php defined('SYSPATH') or die('No direct access allowed.');

class S1_Helper_OAUTH_AccessToken
{
  protected $_values = array();

  public function __construct($encrypted)
  {


    $values = self::unpack($encrypted);
    if( $values !== FALSE )
      {
	$this->_values = $values;
      }
  }

  public static function unpack($encrypted)
  {
    $cert = Kohana::$config->load('kohana-s1-rest-oauth.certificate');
    $encrypted = base64_decode($encrypted);

    $public_key = openssl_pkey_get_public($cert);
    if( $public_key === FALSE )
      {
	//return openssl_error_string();
	return FALSE;
      }

    if( openssl_public_decrypt($encrypted, $token_str, $public_key) )
      {
	$data = unpack("Vversion/Vexpiration/a*data", $token_str);
	$d = explode("\x00", $data['data']);
	$data['user_dn'] = $d[0];
	$data['scopes'] = explode(",", $d[1]);
	unset($data['data']);
	return $data;
      }
    else
      {
	return FALSE;
      }
  }

  public function is_expired()
  {
    return time() > $this->expiration;
  }


  public function has_access($scope)
  {
    return in_array($scope, $this->scopes, TRUE);
  }

  public function __get($column)
  {
    if( array_key_exists($column, $this->_values) )
      {
	return $this->_values[$column];
      }
  }
}