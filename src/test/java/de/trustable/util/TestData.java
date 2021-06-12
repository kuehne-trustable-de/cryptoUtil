/**
 * 
 */
package de.trustable.util;


/**
 * define some generally useful test data
 * 
 * @author ak
 *
 */
public class TestData {

  public final static String SampleCSRBase64 = "-----BEGIN CERTIFICATE REQUEST-----\n"
      + "MIIBmTCCAQICAQAwQDELMAkGA1UEBhMCREUxFjAUBgNVBAoTDXRydXN0YWJsZSBM\n"
      + "dGQxGTAXBgNVBAMTEHJlcTE0MzgwOTY3NzA4MDMwgZ8wDQYJKoZIhvcNAQEBBQAD\n"
      + "gY0AMIGJAoGBAItotXZo1UQIYmPSw+BDd8Z6kKoXfuHCnY64qTATJAuEuCBvJ1R0\n"
      + "ucKQJFlBt+zO5dCFv0gttXpr17fmCw+p4VTUoden12yOQy1fz888DHOsqD1aIMdF\n"
      + "wa2sJxV21DeILKoE/o+9mZxETl7uVt3/Omar3Pska47GwBi3Z8TpSRndAgMBAAGg\n"
      + "GTAXBgkqhkiG9w0BCQcxChMIcGFzc3dvcmQwDQYJKoZIhvcNAQEFBQADgYEAb3CF\n"
      + "iSESik+TEarehSVCJ4QtXvbtNTP3KhS/eGPaxEBfAKRUnN4hwTPVGZy4yPX+9bYx\n"
      + "o/BJTiYt35uFTdApwfg3/H/hB2snWKkqGMJPqI4wEBNwPvkgbiwq8xR0dlVZl8yj\n"
      + "yEndY1bVZGgzF/S8gtxEQQiNvjwKHaczTqqwkVU=\n"
      + "-----END CERTIFICATE REQUEST-----";
  
  public final static String SampleCertificateBase64 = "-----BEGIN CERTIFICATE-----\n"
      + "MIICwzCCAaugAwIBAgIIZpYfuXF+u9YwDQYJKoZIhvcNAQELBQAwEDEOMAwGA1UE\n"
      + "AwwFU3ViQ0EwHhcNMTUwODAzMDcyOTIxWhcNMTcwODAyMDcyOTIxWjA2MTQwMgYD\n"
      + "VQQDDCtjbj10cnVzdGFibGUgdGVzdCBlZSwgbz10cnVzdGFibGUgTHRkLCBjPURF\n"
      + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCY7IhT2vvPF36YgWgNC8gCyr8p\n"
      + "LmaoMYU62yY2yTNOO+xPtkxtzgUEXYTVOxj2Ad0u3fx0B+m4iqB2x//3mhpUzBbb\n"
      + "4M7fRs032Cjpdrp7cjO0/kYvvt6Gl6cE2Lk8F0hdDzIJIeCwyVBMNNi/PW3eki02\n"
      + "kRE5C3W1JJmWOCyZcQIDAQABo38wfTAdBgNVHQ4EFgQUXiclhNJov03+4IkdZmlu\n"
      + "oubJJ3gwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBT8KAA3Lnxl6S0f3Pk4/arT\n"
      + "SMnULzAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUF\n"
      + "BwMEMA0GCSqGSIb3DQEBCwUAA4IBAQA2EU/hoUsmv7eAK4bTwILZpnZFZGG6rurm\n"
      + "JtVARp/bfrFV0etvYdURnSTOk8wwxOv061MhXuDMdfyMoz9zMDMNZkYLtwlne9ZE\n"
      + "k1UH792Tx32aIUYNAMJz5E68/oJd3e0n/PhWToqrUZaHjZh01OSI8/bstuUoRkQj\n"
      + "3ZTnonQEzQdGIp5UF9x5PZAfzNmh/X85A3o9Kzn/MZe1Eq2B40zcRrxEpl597OU4\n"
      + "1ui9vI1JU09BtOaNxkx/mzJ7J8wru2+RMP7gqcFr7NhHudJofri9+gzHEKN7MLwe\n"
      + "nmo2nmjvMkyuB7dMcr5/j3o/nLK8LEWAwvK8p7lD7JxHREYfa6A3\n"
      + "-----END CERTIFICATE-----";

  
  public final static String ValidCMPCertificateRequestBase64 = 
      "MIICNTCB/QIBAqRCMEAxCzAJBgNVBAYMAkRFMRYwFAYDVQQKDA10cnVzdGFibGUgTHRkMRkwFwYDVQQDDBByZXExNDU0NDQ0NjIyOTg0pBUwEzERMA8GA1UEAwwIQWRtaW5DQTGgERgPMjAxNjAyMDIyMDIzNDlaoUAwPgYJKoZIhvZ9B0INMDEEFKOkpRjuv9EFms8xuZvdc7Uejd8NMAcGBSsOAwIaAgID6DAMBggrBgEFBQgBAgUAohQEEmtleUlkMTQ1NDQ0NDYyOTY5NKQcBBp0cmFuc2FjdGlvbklkMTQ1NDQ0NDYyOTY5NKUUBBJub25jZTE0NTQ0NDQ2Mjk2OTSgggEYMIIBFDCCARAwggEKAghlU5Gh9/XWGDCB/aMVMBMxETAPBgNVBAMMCEFkbWluQ0ExpUIwQDELMAkGA1UEBgwCREUxFjAUBgNVBAoMDXRydXN0YWJsZSBMdGQxGTAXBgNVBAMMEHJlcTE0NTQ0NDQ2MjI5ODSmgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAICWMbS2C+sEuVCOV6PTQD5ZK2jIiCDXW3vEmAwggtxHeS64cxZppb2YbZvBtTCDQfamUfkR17TGjS3LAMhgyNrj0Q52J8Qvo1bLjSF4NVVrPpNVqa4ycln4DYD/+eNfwvH8E3MMV8GuQJRwp4uAaILqWhPJgfNfAA2mb/k1TlMrAgMBAAGAAKAXAxUAmypuR5H4+Eq3vsqyGOLtlRRgJII=";

  public final static String ValidCMPRevocationRequestBase64 = 
      "MIIBSjCB+gIBAqRCMEAxGTAXBgNVBAMMEHJlcTE0NTQ0NDM5NDEwNzQxFjAUBgNVBAoMDXRydXN0YWJsZSBMdGQxCzAJBgNVBAYTAkRFpBIwEDEOMAwGA1UEAwwFU3ViQ0GgERgPMjAxNjAyMDIyMjQ2MjFaoUAwPgYJKoZIhvZ9B0INMDEEFHGGRyM+Dr1Dt+tZZ+5tMQ3LyH+cMAcGBSsOAwIaAgID6DAMBggrBgEFBQgBAgUAohQEEmtleUlkMTQ1NDQ1MzE4MTczMaQcBBp0cmFuc2FjdGlvbklkMTQ1NDQ1MzE4MTczMaUUBBJub25jZTE0NTQ0NTMxODE3MzGrMjAwMC4wHoEITgudrM2TE+ijEjAQMQ4wDAYDVQQDDAVTdWJDQTAMMAoGA1UdFQQDCgEAoBcDFQAJwiP6rinQhP4Q5QPCZycQo3QIDQ==";
  
  public final static String ValidCMPResponseBase64 = 
      "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";
  
  public final static String BrokenCMPResponseBase64 = 
      "MIH9MIG5AgECpBUwEzERMA8GA1UEAwwIQWRtaW5DQTGkQjBAMQswCQYDVQQGDAJERTEWMBQGA1UECgwNdHJ1c3RhYmxlIEx0ZDEZMBcGA1UEAwwQcmVxMTQ0MDYyMzYyNDE3NKARGA8yMDE1MDgyNjIxMjUwOFqkHAQadHJhbnNhY3Rpb25JZDE0NDA2MjQzMDc5MDelEgQQWNvVY7clYmzsDEXshESfD6YUBBJub25jZTE0NDA2MjQzMDc5MDehPzA9MDswOQIEz5HDbjAxAgECMCgMJkVtYWlsIGFkZHJlc3MgY2Fubm90IGJlIGVtcHR5IG9yIG51bGwuAwIAAQ==";
}
