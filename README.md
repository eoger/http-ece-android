# encrypted-content-encoding

A simple implementation of [Encrypted Content-Encoding for HTTP](https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-02)

## Tests
The tests can be run by executing the command `./gradlew connectedAndroidTest` on Unix-like systems
or `./gradlew.bat connectedAndroidTest` on Windows.  
An Android device must be connected on the computer running the tests (either an emulator or a physical device).

## Use

```Java
import org.mozilla.httpece.HttpEce;

...

HttpEce.Params params = new HttpEce.Params();
params.key = /* randomBytes(16); */
params.salt = /* randomBytes(16); */

byte[] input = /* randomBytes(100); */

byte[] encrypted = httpEce.encrypt(input, params);
byte[] decrypted = httpEce.decrypt(encrypted, params);
MoreAsserts.assertEquals(input, decrypted);
```

This also supports the static-ephemeral ECDH mode.
