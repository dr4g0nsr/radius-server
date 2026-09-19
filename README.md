# RADIUS Server

A PHP-based RADIUS server implementation designed for ISP administration and network authentication.

## Overview

This is a lightweight, PHP-based RADIUS server that provides authentication services for network access. It's designed to work with existing PHP applications that need to communicate with RADIUS databases while offering flexibility to implement custom authentication systems.

## Compatibility

Tested and works on PHP 8.1 and below. Should work on all PHP 7.x versions as well. PHP 5.x and earlier are not recommended due to security and performance concerns.

## Why Use a PHP-Based RADIUS Server?

Many applications are written in PHP that communicate with RADIUS databases to update and synchronize their own databases. This approach is unnecessary when using this server, as you can override methods to implement your own authentication system for logging users.

## Suitable Applications

This server is primarily suited for ISP administration programs. Beyond simple login functionality, it can perform additional tasks such as:
- Disconnecting users under certain conditions
- Implementing custom authentication logic
- Extending beyond basic RADIUS functionality

## Performance

Performance testing on an i5 processor shows:
- 30,000 requests per second on one core with PHP 7.x
- 7,000 requests per second with PHP 5.x

This should be sufficient for most use cases, as database operations typically become the bottleneck rather than PHP processing.

## Configuration

Configuration is handled through the `config.php` file in the project root:

```php
const DEBUG = false;
$config = [
    'serverip' => '0.0.0.0',
    'serverport' => 1812,
    'secret' => 'secret',
    'receive_buffer' => 65535,
    'auth_method' => 'File',
    'debug' => RADIUS_DEBUG,
];
```

### Authentication Methods

The `auth_method` parameter specifies the authentication method used to provide authentication and attributes. To use a custom authentication method, you need to create a class with the same name. Your class should contain implementation for a specific authentication source such as database.

The default "File" authentication method is a simple file reader that refreshes every 60 seconds. It serves as an example of how to implement custom authentication methods. For production environments, we recommend using Redis due to its speed and simplicity.

Custom authentication classes should be placed in the `classes/auth` directory.
