# RADIUS-SERVER

This is PHP-based radius server.

It's tested and works on PHP up to 8.1, it should work on all 7.X as well, I do not recommend to use 5.X and earlier.

**Why use php based radius?**

Becouse many applictions are written in PHP that communicate with radius DB to update and synchronize own DB. This is unnecessary as you can override methods to implement your own system for logging the users.

**Which applications is suited to use this?**

Mainly ISP administration program. Script can do not only login like radius do but many more, like disconnecting users at some condition. You can also implement your system.

**Isn't this very slow to do in PHP?**

In my test machine which is i5 i can process 30.000 req/sec on one core and using PHP7. In PHP5 i get around 7000. This should be enough for most people as your bottleneck will probalby by DB not PHP.

**Config file**

In root of the project in config.php you can configure some stuff:

```
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

Here auth_method is authentication method used to provide auth and attributes. You need to have class with same name if you want to change this. Your class should contain implementation of specific source like database. "File" is simple file reader that is refreshed every 60 seconds, it is used as example how to do this. I recommend using redis for this purpose as it is very fast and simple.

You class should exists in classes/auth directory.
