# RADIUS-SERVER

This is PHP-based radius server.

Why use php based radius?
Becouse many applictions are written in PHP that communicate with radius DB to update and synchronize own DB. This is unnecessary as you can override methods to implement your own system for logging the users.

Which applications is suited to use this?
Mainly ISP administration program. Script can do not only login like radius do but many more, like disconnecting users at some condition. You can also implement your system.

Isn't this very slow to do in PHP.
In my test machine which is i5 i can process 30.000 req/sec on one core and using PHP7. In PHP5 i get around 7000. This should be enough for most people as your bottleneck will probalby by DB not PHP.

Why didn't you run threaded server?
Tried but didn't work due to some problem (probalby with threading system) that i cannot solve.
