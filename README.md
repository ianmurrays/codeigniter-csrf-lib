# CodeIgniter CSRF Library

This library automatically protects all your forms against Cross-Site Request Forgery attacks, more
commonly refered to as CSRF.

Just put the `application/hooks/csrf.php` in your hooks folder, and the `application/config/hooks.php` 
file in your hooks.php config file (or add the content in case you're already using a hook), and you're done!

The only caveat is that ajax POST requests will get rejected once the library is
installed. To fix this you need to include the CSRF token in your requests. This
token is injected into the `<head>` of your files automatically, so all you need 
to do is get it using any javascript framework and include it in the request. Check
the two lines just befor the ending your `<head>` (`</head>`) to figure it out.

## License

License is the MIT license. This project belongs to [linkigniter](https://github.com/linkworks/linkigniter).
