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

/**
 * Main class to run the crypter from command line.
 * <p/>
 * The following two options exist:
 * <p/>
 * <code>
 * cz.zuran.blog.Main decrypt <i>"password"</i> <i>"string to decrypt"</i>
 * cz.zuran.blog.Main encrypt <i>"password"</i> <i>"string to encrypt"</i>
 * </code>
 * <p/>
 * Date: 22.2.11 Time: 17:42
 *
 * @author Tomas Langer (tomas.langer@google.com)
 */
public class Main {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            usage();
        } else {
            String command = args[0];
            String password = args[1];
            String theString = args[2];

            if (command.equals("decrypt")) {
                decrypt(password, theString);
            } else if (command.equals("encrypt")) {
                encrypt(password, theString);
            } else {
                usage();
            }
        }

    }

    private static void encrypt(String password, String theString) throws Exception {
        System.out.println(OpenSslCrypter.encrypt(theString, password));
    }

    private static void decrypt(String password, String theString) throws Exception {
        if (OpenSslCrypter.isEncrypted(theString)) {
            System.out.println(OpenSslCrypter.decrypt(theString, password));
        } else {
            System.err.println("The provided string is not ecrypted using the expected method.");
            usage();
        }
    }

    private static void usage() {
        System.err.println("Program requires three parameters: command (encrypt|decrypt) password string");
    }
}
