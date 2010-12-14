/*
Copyright (c) 2010 Tomas Langer (tomas.langer@gmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */
package cz.zuran.blog;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Tests the OpenSslCrypter with known encrypted strings and their meanings.
 *
 * @author Tomas Langer (tomas.langer@maersk.com)
 */
public class OpenSslCrypterTest {
    @Test
    public void testCrypter() throws Exception {
        testDecrypter("blogpassphrase", "U2FsdGVkX1+9/5jkQcrjZZZHWn/SBThhw9ntqJRRDsE=", "Hello blog!");
        testDecrypter("blogpassphrase", "U2FsdGVkX1/EdBJIwqB11in/KfdC7Cp02AwdMlAWm/Y=", "Hello blog!");
        testDecrypter("nothardcoded", "U2FsdGVkX1/r7SIR5e2ZhfbxmAMXiKBc5/6og0sRKq4=", "Hello blog!");

    }

    @Test
    public void testIsEncrypted() {
        testIsEncrypted("hula hula", false);
        testIsEncrypted("Random string", false);
        testIsEncrypted("U2FsdGVkX18GqS1oFTNzK9MqZAhytAbHXMiDrwFMe2A=", true);
        testIsEncrypted("U2FsdGVkX19nvI3bLwUVxe9eFeI50CPKhQVX7latnJg=", true);
    }

    private void testIsEncrypted(String toTest, boolean isEncrypted) {
        boolean actual = OpenSslCrypter.isEncrypted(toTest);
        assertTrue("String " + toTest + " is actually " + (isEncrypted ? "" : "not ") + "encrypted. Wrong result.", actual == isEncrypted);
    }

    private void testEncrypter(String password, String original) throws Exception {
        String encrypted = OpenSslCrypter.encrypt(original, password);
        String decrypted = OpenSslCrypter.decrypt(encrypted, password);

        assertEquals(original, decrypted);
    }

    private void testDecrypter(String password, String encrypted, String expected) throws Exception {
        String decrypted = OpenSslCrypter.decrypt(encrypted, password);

        assertEquals(expected, decrypted);
    }
}
