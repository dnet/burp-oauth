OAuth plugin for Burp Suite
===========================

Building
--------

 - Install the dependencies, in case of libraries, put the JARs into `lib`
 - Download the [Burp Extender API][1] and unpack it into `src``
 - Copy `OAuthConfig.sample.java` to `src/OAuthConfig.java` and modify it to your needs
 - Execute `ant`, and you'll have the plugin ready in `burp-oauth.jar`

Dependencies
------------

 - JDK 1.6+ (tested on OpenJDK `1.6.0_27`, Debian/Ubuntu package: `openjdk-6-jdk`)
 - Apache ANT (Debian/Ubuntu package: `ant`)
 - `oauth-signpost` http://code.google.com/p/oauth-signpost/
 - Apache Commons Codecs: http://commons.apache.org/codec/
 - JUnit 4+ (only required for testing)

License
-------

The whole project is available under MIT license, see `LICENSE.txt`.

Known limitations
-----------------

 - Configuration has to be done at compile time using `OAuthConfig.java`

  [1]: http://portswigger.net/burp/extender/api/burp_extender_api.zip
