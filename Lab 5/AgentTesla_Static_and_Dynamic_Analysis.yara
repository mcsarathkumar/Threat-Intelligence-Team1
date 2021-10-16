/*
Title       : Agent Tesla - Static and Dynamic Analysis
Author      : Team 1
Created On  : August 10, 2021
*/

rule AgentTeslaStaticDynamicRule
{
    meta:
        description = "AgentTeslaStaticDynamicRule"
        os = "mswindows"
        filetype = "pe"
        maltype = "trojan"

    strings:
        // These certs are common between 5ace35afbf13d16d5b21ae38befde4a0418c4fffabe3c09f06888eb5aa83c063 
        // and 90c99275bfea4f4084d07b4a0a044f81e6c9fbe19fba688a7fe8a0be46004acf
        $cert1 = "http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0"
        $cert2 = "http://ocsp.digicert.com0C"
        $cert3 = "http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0P"
        $cert4 = "http://crl4.digicert.com/sha2"
        $cert5 = "http://crl3.digicert.com/sha2"
        $cert6 = "http://crl4.digicert.com/DigiCertAssuredIDRootCA.crl0"
        $cert7 = "http://ocsp.digicert.com0O"
        $cert8 = "http://cacerts.digicert.com/DigiCertSHA2AssuredIDTimestampingCA.crt0"
        $cert9 = "https://www.digicert.com/CPS0"

        $obfuscation1 = "FromBase64String"
        $sleep = "Sleep"

        $first1 = "LoadLibrary"
        $first2 = "GetProcAddress"

        $intermediate1 = "VSTestVideoRecorder.exe"

        $second1 = "https://www.tapatalk.com/groups/vvmm"
        $second2 = "https://github.com/SilverGreen93/CDPExplorer"
        $second3 = "1.0.0.1"
        $second4 = "get_PictureBox1"
        $second5 = "set_PictureBox1"
        $second6 = "get_GroupBox1"
        $second7 = "set_GroupBox1"
        
    condition:
        (4 of ($cert*) and any of ($obfuscation*) and $sleep and (all of ($first*) or all of ($intermediate*))) or
        4 of ($second*)
}
