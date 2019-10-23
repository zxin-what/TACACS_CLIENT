package com.venustech.tacacs.protocol;

import com.venustech.tacacs.UserInterface;
import com.venustech.tacacs.client.TacacsFuture;
import com.venustech.tacacs.client.TacacsMessageHandler;
import com.venustech.tacacs.protocol.entity.*;
import com.venustech.tacacs.protocol.entity.base.Argument;
import com.venustech.tacacs.protocol.entity.base.Header;
import com.venustech.tacacs.protocol.entity.base.Packet;
import com.venustech.tacacs.protocol.enums.TACACS_PLUS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author zhangxin
 * 2018/8/28
 */
public class ClientSession extends Session{

    private Logger logger = LoggerFactory.getLogger(ClientSession.class);

    private static final int TIMEOUT_MILLIS = 5000;
    private static final boolean DEBUG = false;
    private final UserInterface ui;
    private final boolean singleConnect;
    private byte headerFlags;
    private static final AtomicInteger PPP_ID = new AtomicInteger();//chap
    private static final int CHAP_CHALLENGE_LENGTH = 16;


    public ClientSession(TACACS_PLUS.AUTHEN.SVC svc, String port, String rem_addr, byte priv_lvl, TacacsMessageHandler tacacs, boolean singleConnect, boolean unencrypted) {
        this(svc, port, rem_addr, priv_lvl, tacacs, null, singleConnect, unencrypted);
    }

    /**
     *
     * @param svc
     * @param port
     * @param rem_addr
     * @param priv_lvl
     * @param tacacs
     * @param ui
     * @param singleConnect
     * @param unencrypted
     */
    public ClientSession(TACACS_PLUS.AUTHEN.SVC svc, String port, String rem_addr, byte priv_lvl, TacacsMessageHandler tacacs, UserInterface ui, boolean singleConnect, boolean unencrypted)
    {
        super(svc, port, rem_addr, priv_lvl, tacacs, null);
        this.ui = ui;
        this.singleConnect = singleConnect;
        this.headerFlags = FLAG_ZERO;
        if (singleConnect) {
            this.headerFlags |= TACACS_PLUS.PACKET.FLAG.SINGLE_CONNECT.code();
        }
        if (unencrypted){
            this.headerFlags |= TACACS_PLUS.PACKET.FLAG.UNENCRYPTED.code();
        }
    }

    @Override
    public boolean isSingleConnectMode(){
        return super.isSingleConnectMode() && singleConnect;
    }

    @Override
    public synchronized boolean handlePacket(Packet packet) throws Exception{
        super.handlePacket(packet);
        boolean result = false;
        switch (packet.header.type){
            /** 认证 **/
            case AUTHEN:
                AuthenReply authenReply = (AuthenReply)packet;
                switch (authenReply.status){
                    case PASS:
                        result = true;
                        break;
                    case GETDATA:
                        if(ui == null){throw new IOException("no user input data");}
                        String data = ui.getUserInput(authenReply.server_msg, authenReply.hasFlag(TACACS_PLUS.REPLY.FLAG.NOECHO), authenReply.status);
                        TacacsFuture getData = tacacs.sendTacacsPacket(new AuthenContinue
                                (
                                        packet.getHeader().next(TACACS_PLUS.PACKET.VERSION.v13_0),
                                        data,
                                        FLAG_ZERO
                                ));
                        Packet pdata = (Packet) getData.get();
                        result = handlePacket(pdata);
                        break;
                    case GETUSER:
                        if (ui==null) { throw new IOException("No interactive user interface available."); }
                        String username = ui.getUserInput(authenReply.server_msg, authenReply.hasFlag(TACACS_PLUS.REPLY.FLAG.NOECHO), authenReply.status); // blocks for user input
                        TacacsFuture getUser = tacacs.sendTacacsPacket(new AuthenContinue
                                (
                                        packet.getHeader().next(TACACS_PLUS.PACKET.VERSION.v13_0),
                                        username,
                                        FLAG_ZERO
                                ));
                        Packet user = (Packet) getUser.get();
                        result = handlePacket(user);
                        break;
                    case GETPASS:
                        if (ui==null) { throw new IOException("No interactive user interface available."); }
                        String password = ui.getUserInput(authenReply.server_msg, authenReply.hasFlag(TACACS_PLUS.REPLY.FLAG.NOECHO), authenReply.status); // blocks for user input
                        TacacsFuture getPass = tacacs.sendTacacsPacket(new AuthenContinue
                                (
                                        packet.getHeader().next(TACACS_PLUS.PACKET.VERSION.v13_0),
                                        password,
                                        FLAG_ZERO
                                ));
                        Packet pass = (Packet) getPass.get();
                        result = handlePacket(pass);
                        break;
                    case RESTART:
                        break;
                    case ERROR:
                        break;
                    case FAIL:
                        break;
                    case FOLLOW:
                        break;
                    default:
                        end(packet);
                        break;
                }
                break;
            /** 授权 **/
            case AUTHOR:
                AuthorReply authorReply = (AuthorReply)packet;
                if (authorReply.isOK()){
                    result = true;
                }
                logger.info("author reply mode is : " + authorReply.status);
                break;
            /** 审计 **/
            case ACCT:
                end(packet);
                break;
            default:
                logger.info("invalid type for packet");
                break;
        }
        return result;
    }

    /**
     * ASCII 认证
     * @return
     * @throws Exception
     */
    public synchronized AuthenReply authenticate_ASCII() throws Exception {
        TacacsFuture tacacsFuture = tacacs.sendTacacsPacket(new AuthenStart
                (
                        new Header(this.headerFlags, TACACS_PLUS.PACKET.VERSION.v13_0, TACACS_PLUS.PACKET.TYPE.AUTHEN,id),
                        TACACS_PLUS.AUTHEN.ACTION.LOGIN,
                        priv_lvl,
                        TACACS_PLUS.AUTHEN.TYPE.ASCII,
                        TACACS_PLUS.AUTHEN.SVC.NONE,
                        "", // server will prompts for username
                        port,
                        rem_addr,
                        "" // server will prompt for password
                ));
        return (AuthenReply) tacacsFuture.get();
    }


    /**
     * PAP认证.
     *
     * @param username
     * @param password
     * @return
     * @throws java.util.concurrent.TimeoutException
     * @throws java.io.IOException
     */
    public synchronized AuthenReply authenticate_PAP(String username, String password) throws Exception {

        TacacsFuture tacacsFuture = tacacs.sendTacacsPacket(new AuthenStart
                (
                        new Header(this.headerFlags, TACACS_PLUS.PACKET.VERSION.v13_1, TACACS_PLUS.PACKET.TYPE.AUTHEN,id),
                        TACACS_PLUS.AUTHEN.ACTION.LOGIN,
                        priv_lvl,
                        TACACS_PLUS.AUTHEN.TYPE.PAP,
                        TACACS_PLUS.AUTHEN.SVC.NONE,
                        username,
                        port,
                        rem_addr,
                        password
                ));
        return (AuthenReply) tacacsFuture.get();
    }


    /**
     * 挑战码
     * @param username
     * @param password
     * @return
     * @throws java.util.concurrent.TimeoutException
     * @throws java.io.IOException
     */
    public synchronized AuthenReply authenticate_CHAP(String username, String password) throws Exception {
        byte[] data = new byte[1+CHAP_CHALLENGE_LENGTH+16]; // PPP ID byte + challenge + MD5 hash response
        // The PPP ID needs to be relatively unique per login attempt
        data[0] = (byte)PPP_ID.getAndIncrement();
        // In CHAP for TACACS+, the client-side generates the challenge.
        byte[] challenge = Session.generateRandomBytes(CHAP_CHALLENGE_LENGTH);
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(data[0]);
        md.update(password.getBytes(StandardCharsets.UTF_8));
        md.update(challenge);
        byte[] response = md.digest();
        System.arraycopy(challenge, 0, data, 1, challenge.length);
        System.arraycopy(response, 0, data, 1+challenge.length, response.length);

        TacacsFuture tacacsFuture = tacacs.sendTacacsPacket(new AuthenStart
                (
                        new Header(this.headerFlags, TACACS_PLUS.PACKET.VERSION.v13_1, TACACS_PLUS.PACKET.TYPE.AUTHEN,id),
                        TACACS_PLUS.AUTHEN.ACTION.LOGIN,
                        priv_lvl,
                        TACACS_PLUS.AUTHEN.TYPE.CHAP,
                        TACACS_PLUS.AUTHEN.SVC.NONE,
                        username,
                        port,
                        rem_addr,
                        data
                ));
        return (AuthenReply)tacacsFuture.get();
    }

    /**
     * 授权
     * @param username
     * @param authen_meth
     * @param authen_type
     * @param authen_svc
     * @param args
     * @return
     * @throws Exception
     */
    public synchronized AuthorReply authorize(String username, TACACS_PLUS.AUTHEN.METH authen_meth, TACACS_PLUS.AUTHEN.TYPE authen_type, TACACS_PLUS.AUTHEN.SVC authen_svc, Argument[] args) throws Exception {
        TacacsFuture  tacacsFuture = tacacs.sendTacacsPacket(new AuthorRequest
                (
                        new Header(this.headerFlags, TACACS_PLUS.PACKET.VERSION.v13_0, TACACS_PLUS.PACKET.TYPE.AUTHOR,id),
                        authen_meth,
                        (byte)0,
                        authen_type,
                        authen_svc,
                        username,
                        port,
                        rem_addr,
                        args
                ));
        return (AuthorReply)tacacsFuture.get();
    }

}
