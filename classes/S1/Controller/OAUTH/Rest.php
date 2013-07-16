<?php defined('SYSPATH') or die('No direct script access.');
  
class S1_Controller_OAUTH_Rest extends S1_Controller_Rest_Template
{

  /* Holder for parsed Access Token */
  protected $access_token = NULL;
  
  /*
   * FALSE: don't check OAUTH signature
   * 'scope': ensure OAUTH signature is valid for 'scope'
   * array('scope.a', 'scope.b'): ensure OAUTH signature is valid for BOTH scope.a and scope.b
   * array('GET' => 'scope.a', 'POST' => 'scope.b'): ensure OAUTH signature has scope.a when 
   *         HTTP method is GET and scope.b when HTTP method is POST
   * array('GET' => array('scope.a', 'scope.b'), 'PUT' => array('scope.b', 'scope.c'))
   */

  public $oauth_required = FALSE;
  
  public $oauth_actions = FALSE;
  
  
  /**
   * The before() method is called before your controller action.
   * In our template controller we override this method so that we can
   * set up default values. These variables are then available to our
   * controllers if they need to be modified.
   */
  public function before()
  {
    if( $this->oauth_required !== FALSE || $this->oauth_actions !== FALSE )
      {

	$access_token = $this->request->headers('Authorization');
	if( $access_token !== NULL )
	  {
	    if( substr($access_token, 0, 7) === "Bearer ")
	      {
		$access_token = substr($access_token, 7);
	      }
	    else
	      {
		$access_token = NULL;
	      }
	  }

	if( $access_token === NULL )
	  {
	    $access_token = $this->request->query('access_token');
	  }

	$this->access_token = new S1_Helper_OAUTH_AccessToken($access_token);
      }

    parent::before();
  }
  
  protected function token_has_access($access_required, S1_Helper_OAUTH_AccessToken $AccessToken)
  {
    if( $access_required === FALSE )
      {
	return TRUE;
      }

    if( is_array($access_required) === FALSE )
      {
	return $AccessToken->has_access($access_required);
      }

    if( $this->is_assoc($access_required) === FALSE )
      {
	foreach($access_required as $scope_id)
	  {
	    if( $AccessToken->has_access($scope_id) === FALSE )
	      {
		return FALSE;
	      }
	  }

	return TRUE;
      }
    else
      {
	if( array_key_exists($this->request->method(), $access_required) === TRUE )
	  {
	    $access_required = $access_required[$this->request->method()];
	    return $this->token_has_access($access_required, $AccessToken);
	  }
	else
	  {
	    return FALSE;
	  }
      }
  }

  protected function check_access($user = NULL)
  {
    if( $user !== NULL )
      {
	return parent::check_access($user);
      }

    /* Option A: Check access based on logged in user (if there is one). */
    if( Auth::instance()->logged_in() )
      {

	$this->user = $user = Auth::instance()->get_user();
	return parent::check_access($user);
      }
    else
      {
	/* Option B: Check access based on OAUTH */
	/* Option B Stage 1: Handled by Controller_OAUTH_Rest, checks scope of access token. */

	if( $this->access_token->is_expired() === TRUE )
	  {
	    $this->throw_error(401, 'Access Token is expired');
	  }
	
	if( $this->token_has_access($this->oauth_required, $this->access_token) === FALSE )
	  {
	    $this->throw_error(401, 'Access Token does not have proper scope');
	  }
	

	/* Option B Stage 2: Check access based on user_dn provided by access token. */
	$this->user = $user = NULL;
	if( $this->access_token !== NULL)
	  {
	    $this->user = $user = ORM::factory('User', array('user_dn' => $this->access_token->user_dn));
	  }
	else
	  {
	    $this->user = $user = ORM::factory('User');
	  }

	return parent::check_access($user);
      }

    return FALSE;
  }

}