
import org.junit.Test;
import static org.junit.Assert.*;
import org.luis.cert.test.JKSUtil;

/**
 *
 * @author luis
 */
public class JKSTest {

    @Test
    public void test() throws Throwable {
        assertEquals(
                JKSUtil.extractFingerprintFromJKSCert("test.jks", "test-alias", "123456"),
                JKSUtil.extractFingerprintFromPEM("test.pem"));
    }
}
