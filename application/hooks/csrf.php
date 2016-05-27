<?php
/**
* CSRF Protection Class
*/
class CSRF_Protection
{
  /**
   * Holds CI instance
   *
   * @var CI instance
   */
  private $CI;
  
  /**
   * Name used to store token on session
   *
   * @var string
   */
  private static $token_name = 'li_token';
  
  /**
   * Stores the token
   *
   * @var string
   */
  private static $token;
  
  // -----------------------------------------------------------------------------------
  
  public function __construct()
  {
    $this->CI =& get_instance();
  }
  
  // -----------------------------------------------------------------------------------
  
  /**
   * Generates a CSRF token and stores it on session. Only one token per session is generated.
   * This must be tied to a post-controller hook, and before the hook
   * that calls the inject_tokens method().
   *
   * @return void
   * @author Ian Murray
   */
  public function generate_token()
  {
    if ( ! $this->CI->config->item('linkigniter.enable_csrf_protection'))
    {
      return;
    }
    
    // Load session library if not loaded
    $this->CI->load->library('session');
    
    if ($this->CI->session->userdata(self::$token_name) === FALSE)
    {
      // Generate a token and store it on session, since old one appears to have expired.
      self::$token = bin2hex(openssl_random_pseudo_bytes(16));

      $this->CI->session->set_userdata(self::$token_name, self::$token);
    }
    else
    {
      // Set it to local variable for easy access
      self::$token = $this->CI->session->userdata(self::$token_name);
    }
  }
  
  // -----------------------------------------------------------------------------------
  
  /**
   * This injects hidden tags on all POST forms with the csrf token.
   * Also injects meta headers in <head> of output (if exists) for easy access
   * from JS frameworks.
   *
   * @return void
   * @author Ian Murray
   */
  public function inject_tokens()
  {
    if ( ! $this->CI->config->item('linkigniter.enable_csrf_protection'))
    {
      // This has to be here otherwise nothing is sent to the browser
      $this->CI->output->_display($this->CI->output->get_output());
      return;
    }
    
    $output = $this->CI->output->get_output();
    
    // Inject into form
    $output = preg_replace('/(<(form|FORM)[^>]*(method|METHOD)="(post|POST)"[^>]*>)/',
                           '$0<input type="hidden" name="' . self::$token_name . '" value="' . self::$token . '">', 
                           $output);
    
    // Inject into <head>
    $output = preg_replace('/(<\/head>)/',
                           '<meta name="csrf-name" content="' . self::$token_name . '">' . "\n" . '<meta name="csrf-token" content="' . self::$token . '">' . "\n" . '$0', 
                           $output);
    
    $this->CI->output->_display($output);
  }
  
  // -----------------------------------------------------------------------------------
  
  /**
   * Validates a submitted token when POST request is made.
   *
   * @return void
   * @author Ian Murray
   */
  public function validate_tokens()
  {  
    if ( ! $this->CI->config->item('linkigniter.enable_csrf_protection'))
    {
      return;
    }
    
    // Is this a post request?
    // @link http://stackoverflow.com/questions/1372147/php-check-whether-a-request-is-get-or-post
    if ($_SERVER['REQUEST_METHOD'] == 'POST')
    {
      // Is the token field set and valid?
      $posted_token = $this->CI->input->post(self::$token_name);
      if ($posted_token === FALSE || $posted_token != $this->CI->session->userdata(self::$token_name))
      {
        // Invalid request, send error 400.
        show_error('Request was invalid. Tokens did not match.', 400);
      }
    }
  }
}
