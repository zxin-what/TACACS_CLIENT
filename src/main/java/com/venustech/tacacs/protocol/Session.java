package com.venustech.tacacs.protocol;

import com.venustech.tacacs.client.TacacsMessageHandler;
import com.venustech.tacacs.protocol.entity.base.Packet;
import com.venustech.tacacs.protocol.enums.TACACS_PLUS;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * @author zhangxin
 * 2018/8/28
 */
public abstract class Session {

    static final byte FLAG_ZERO = (byte) 0x0;
    /** 报头中的公共字段 **/
    protected String rem_addr;
    protected String port;
    protected byte priv_lvl;
    protected TACACS_PLUS.AUTHEN.SVC authen_svc;
    protected byte[] id;
    protected Packet result = null;

    final TacacsMessageHandler tacacs;

    private Thread waitingThread = null;
    private IOException ioe = null;
    private Packet firstPacket = null;



    Session(TACACS_PLUS.AUTHEN.SVC authen_svc, String port, String rem_addr, byte priv_lvl, TacacsMessageHandler tacacs, byte[] id ){
        this.rem_addr = rem_addr;
        this.port = port;
        this.priv_lvl = priv_lvl;
        this.authen_svc = authen_svc;
        this.id = id == null ? generateRandomBytes(4) : id;
        this.tacacs = tacacs;
    }

    boolean handlePacket(Packet p) throws Exception {
        if (firstPacket==null) firstPacket = p;
        return false;
    }

    /** 是否是单连接模式 **/
    boolean isSingleConnectMode(){
        return firstPacket != null && firstPacket.header.hasFlag(TACACS_PLUS.PACKET.FLAG.SINGLE_CONNECT);
    }
    /** 判断sessionId是否合法 **/
    final boolean isID(byte[] id)
    {
        if (id.length != this.id.length) return false;
        for (int i=0; i<id.length; i++) { if (id[i] != this.id[i]) { return false; } }
        return true;
    }

    /** Generate a random byte[], e.g. a session ID for a new client-side session, or a CHAP challenge. */
    final static byte[] generateRandomBytes(int length)
    {
        // Use of SecureRandom per https://www.cigital.com/blog/proper-use-of-javas-securerandom/
        SecureRandom sr;
        try { sr = SecureRandom.getInstance("SHA1PRNG", "SUN"); }
        catch (NoSuchAlgorithmException | NoSuchProviderException e) { sr = new SecureRandom(); }
        byte[] bytes = new byte[length];
        sr.nextBytes(bytes);
        return bytes;
    }

    protected synchronized void end(Packet result) {
        this.result = result;
    }
}
