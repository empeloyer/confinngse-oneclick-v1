package app.ovpn.oneclick

import org.junit.Assert.*
import org.junit.Test

class ValidatorsTest {
    private fun base() = ConnectionForm(host = "203.0.113.7", password = "x")
    private fun ConnectionForm.with(k: Kind, enabled: Boolean = true, port: String? = null, opt1: String? = null, opt2: String? = null): ConnectionForm {
        val s = setting(k)
        return copy(protos = protos + (k to s.copy(enabled = enabled, port = port ?: s.port, opt1 = opt1 ?: s.opt1, opt2 = opt2 ?: s.opt2)))
    }

    @Test fun hostAcceptsIpsAndNames() {
        assertTrue(Validators.isHost("203.0.113.7")); assertTrue(Validators.isHost("vpn.example.com")); assertTrue(Validators.isHost("2001:db8::1"))
    }

    @Test fun hostRejectsInjection() {
        assertFalse(Validators.isHost("1.2.3.4; rm -rf /")); assertFalse(Validators.isHost("a b"))
        assertFalse(Validators.isHost("host'\$(id)")); assertFalse(Validators.isHost(""))
    }

    @Test fun defaultFormIsValid() = assertNull(Validators.validate(base()))

    @Test fun needsAtLeastOneConfig() =
        assertNotNull(Validators.validate(base().with(Kind.OPENVPN, enabled = false)))

    @Test fun duplicatePortsRejectedPerTransport() {
        val f = base().with(Kind.VLESS_REALITY, port = "443").with(Kind.VLESS_GRPC, port = "443")
        assertNotNull(Validators.validate(f))
        // same number on different transports is fine (WireGuard UDP + Reality TCP)
        assertNull(Validators.validate(base().with(Kind.VLESS_REALITY, port = "443").with(Kind.HYSTERIA2, port = "443")))
    }

    @Test fun sshPortIsReserved() =
        assertNotNull(Validators.validate(base().with(Kind.VLESS_REALITY, port = "22")))

    @Test fun perKindOptionsValidated() {
        assertNotNull(Validators.validate(base().with(Kind.WIREGUARD, opt1 = "9000")))
        assertNotNull(Validators.validate(base().with(Kind.VLESS_WS, opt1 = "no-slash")))
        assertNotNull(Validators.validate(base().with(Kind.VLESS_REALITY, opt1 = "x;y")))
        assertNotNull(Validators.validate(base().with(Kind.SHADOWSOCKS, opt1 = "rc4")))
        assertNull(Validators.validate(base().with(Kind.SHADOWSOCKS, opt1 = "aes-256-gcm")))
    }

    @Test fun multiSniLists() {
        assertEquals(listOf("a.com", "b.com", "c.org"), Validators.parseSnis(" A.com, b.com\nc.org,a.com "))
        assertNull(Validators.validate(base().with(Kind.VLESS_REALITY, opt1 = "www.microsoft.com, www.apple.com")))
        assertNull(Validators.validate(base().with(Kind.VLESS_GRPC, opt1 = "a.com,b.com", opt2 = "grpc")))
        assertNotNull(Validators.validate(base().with(Kind.VLESS_REALITY, opt1 = "a.com,x;y")))
        assertNotNull(Validators.validate(base().with(Kind.VLESS_REALITY, opt1 = " , ")))
        assertNotNull(Validators.validate(base().with(Kind.VLESS_REALITY, opt1 = (1..11).joinToString(",") { "h$it.com" })))
    }

    @Test fun sshKindRules() {
        // existing SSH port is allowed for the tunnel kind (unlike other TCP kinds)
        assertNull(Validators.validate(base().with(Kind.SSH)))
        assertNull(Validators.validate(base().with(Kind.SSH, opt2 = "S3cret-pass.1")))
        assertNotNull(Validators.validate(base().with(Kind.SSH, opt1 = "root")))
        assertNotNull(Validators.validate(base().with(Kind.SSH, opt1 = "Bad User")))
        assertNotNull(Validators.validate(base().with(Kind.SSH, opt2 = "short")))
        assertNotNull(Validators.validate(base().with(Kind.SSH, opt2 = "pass word'; id")))
        // tunnel user must not be the login user
        assertNotNull(Validators.validate(base().copy(user = "tunnel1").with(Kind.SSH, opt1 = "tunnel1")))
        assertNotNull(Validators.validate(base().with(Kind.SSH, port = "70000")))
    }

    @Test fun sshGroupIsPlannedLast() {
        val p = buildPlan(base().with(Kind.SSH).with(Kind.HYSTERIA2))
        assertEquals(listOf(Group.OPENVPN, Group.HYSTERIA2, Group.SSH), p.groups)
        assertEquals(1 + Group.OPENVPN.steps.size + Group.HYSTERIA2.steps.size, p.offset(Group.SSH))
    }

    @Test fun planCountsOnlySelectedGroups() {
        val one = buildPlan(base())
        assertEquals(1 + Group.OPENVPN.steps.size + 1, one.labels.size)
        val many = buildPlan(base().with(Kind.VLESS_REALITY).with(Kind.VMESS_WS).with(Kind.HYSTERIA2))
        assertEquals(listOf(Group.OPENVPN, Group.XRAY, Group.HYSTERIA2), many.groups)
        assertEquals(1 + Group.OPENVPN.steps.size, many.offset(Group.XRAY))
        assertEquals(1 + Group.OPENVPN.steps.size + Group.XRAY.steps.size + Group.HYSTERIA2.steps.size + 1, many.labels.size)
    }

    @Test fun ovpnAndWireGuardChecks() {
        val good = "client\nremote 1.2.3.4 1194\n<ca>\n${"x".repeat(600)}\n</ca>\n<cert>\n</cert>\n<key>\n-----BEGIN PRIVATE KEY-----\n</key>\n"
        assertTrue(Validators.looksLikeOvpn(good)); assertFalse(Validators.looksLikeOvpn("client\nremote 1.2.3.4 1194\n"))
        val wg = "[Interface]\nPrivateKey = ${"A".repeat(44)}\nAddress = 10.9.0.2/32\n\n[Peer]\nPublicKey = ${"B".repeat(44)}\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
        assertTrue(Validators.looksLikeWireGuard(wg)); assertFalse(Validators.looksLikeWireGuard("[Interface]"))
    }

    @Test fun linkChecks() {
        assertTrue(Validators.looksLikeLink("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp#n"))
        assertTrue(Validators.looksLikeLink("ssh://tunnel:Passw0rdPass@1.2.3.4:22#phone-ssh"))
        assertFalse(Validators.looksLikeLink("http://evil.example/x")); assertFalse(Validators.looksLikeLink("vless://a b"))
    }

    @Test fun logSanitizer() {
        assertNull(LogSanitizer.clean("-----BEGIN PRIVATE KEY-----", emptyList()))
        assertNull(LogSanitizer.clean("vless://uuid@1.2.3.4:443", emptyList()))
        assertNull(LogSanitizer.clean("ssh://user:pw@1.2.3.4:22", emptyList()))
        assertEquals("login with *** ok", LogSanitizer.clean("login with hunter2 ok", listOf("hunter2")))
    }
}
